"""The Actor model layer for the izba dogfood runner.

Two implementations of one tiny protocol:

- ``OpenRouterModel`` — calls OpenRouter's chat-completions endpoint with a
  system prompt that makes the model the **Actor**: given a journey step's intent
  and the latest observations, decide the *next single* ``izba`` command (or
  signal the step is done). Stdlib ``urllib`` only — no SDK, no pip deps.
- ``FakeModel`` — pops scripted replies; used by every test so the runner is
  exercisable with no API key and no network.

Reply contract (both): a dict ``{"command": "<shell command>"}`` to run the next
action, or ``{"done": true}`` to finish the current step/journey. Each call also
records ``last_cost_usd`` (an *approximate* USD estimate from the API ``usage``
field; 0.0 for the fake).
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

# Approximate blended price for the cheap OpenRouter tier, in USD per 1M tokens.
# Deliberately conservative (rounds the estimate UP) so the budget cap trips
# early rather than late. Real per-model prices vary; this is only a guardrail
# estimate, not billing — actual cost is whatever OpenRouter charges.
APPROX_USD_PER_1M_TOKENS = 1.0

SYSTEM_PROMPT = (
    "You are the Actor in an automated izba dogfooding loop: a developer sitting "
    "at a normal Linux shell, trying to accomplish a task with izba (a CLI that "
    "runs per-project microVM sandboxes for AI coding agents). You are given ONE "
    "user-journey step (an intent and its expected outcome) plus the observations "
    "from the commands run so far. Decide the SINGLE next shell command to run. "
    "Each command is executed via `bash -c` in your working directory, so you have "
    "a real shell: izba is on your PATH, and you can use ordinary tools (cat, "
    "echo/heredocs to create files, curl, git, …) and shell features (pipes, "
    "redirects, quoting). To run a compound command INSIDE a guest use "
    "`izba exec NAME -- sh -c '...'` (and likewise `izba run`). "
    "Respond with ONLY a JSON object, no prose, in one of these two forms:\n"
    '  {"command": "<shell command>"}   to run the next command\n'
    '  {"done": true}                   when the step is satisfied (or cannot proceed).\n'
    "Never repeat a command that already ran with the same result. Prefer the "
    "smallest command that makes progress. Mind shell quoting/escaping. Do not "
    "wrap the JSON in markdown."
)

def _system_content(cli_help: str = "", readme: str = "",
                    context_pack: str = "") -> str:
    """Assemble the Actor system prompt from the fair-test surfaces a real user
    has: run-specific notes (``context_pack``), the product ``README``, and the
    live ``izba --help`` output. Each is optional; with all three empty this
    returns the bare ``SYSTEM_PROMPT`` (keeps the no-seed path stable).

    Layering mirrors how a user actually onboards: first the environment they are
    operating in (context pack), then the docs they read (README), then the exact
    command surface (``--help``). None of these carry spec/source/PR internals —
    that laundering is enforced upstream in Phase 1.
    """
    cli_help = (cli_help or "").strip()
    readme = (readme or "").strip()
    context_pack = (context_pack or "").strip()
    if not (cli_help or readme or context_pack):
        return SYSTEM_PROMPT

    parts = [SYSTEM_PROMPT]
    if cli_help:
        parts.append(
            "For izba itself, use ONLY the subcommands and flags documented in the "
            "`izba --help` output below — do NOT invent izba commands (there is no "
            "`start`, `init`, `list`, ...). You may freely use normal shell tools "
            "around it. Note exec/run take the guest command after `--` (e.g. "
            "`izba run -- uname -s`). If a step truly cannot be done with the "
            'documented surface, reply {"done": true} — do not invent izba flags.'
        )
    if context_pack:
        parts.append("=== run notes (your environment) ===\n" + context_pack)
    if readme:
        parts.append("=== README (product documentation) ===\n" + readme)
    if cli_help:
        parts.append("=== izba help ===\n" + cli_help)
    return "\n\n".join(parts)


_JSON_OBJ_RE = re.compile(r"\{.*\}", re.DOTALL)


def _parse_reply(content: str) -> Dict[str, Any]:
    """Extract the {"command": ...} | {"done": true} object from model content."""
    content = content.strip()
    try:
        obj = json.loads(content)
    except ValueError:
        m = _JSON_OBJ_RE.search(content)
        if not m:
            return {"done": True}
        try:
            obj = json.loads(m.group(0))
        except ValueError:
            return {"done": True}
    if isinstance(obj, dict) and (obj.get("done") or isinstance(obj.get("command"), str)):
        return obj
    return {"done": True}


def _build_user_message(journey: Dict[str, Any], step: Dict[str, Any],
                        observations: List[Dict[str, Any]]) -> str:
    obs_lines = []
    for o in observations[-6:]:  # keep context small + cheap
        obs_lines.append(
            f"- ran `{o.get('command', '')}` -> exit {o.get('exit_code')}; "
            f"stdout: {(o.get('stdout_tail') or '')[-300:]!r}; "
            f"stderr: {(o.get('stderr_tail') or '')[-300:]!r}"
        )
    obs = "\n".join(obs_lines) if obs_lines else "(none yet)"
    return (
        f"Journey: {journey.get('journey_id', '')}\n"
        f"Step intent: {step.get('intent', '')}\n"
        f"Expected outcome: {step.get('expect', '')}\n"
        f"Observations so far:\n{obs}\n\n"
        "Next command JSON:"
    )


class FakeModel:
    """Deterministic model for tests: pops scripted replies; exhausted -> done."""

    def __init__(self, script: List[Dict[str, Any]]):
        self._script = list(script)
        self._i = 0
        self.last_cost_usd = 0.0

    def next_command(self, journey, step, observations) -> Dict[str, Any]:
        self.last_cost_usd = 0.0
        if self._i >= len(self._script):
            return {"done": True}
        reply = self._script[self._i]
        self._i += 1
        return reply


class OpenRouterModel:
    """Calls OpenRouter chat-completions. Report-only: on error returns done."""

    def __init__(self, api_key: str, model_id: str,
                 url: str = OPENROUTER_URL, timeout_s: float = 60.0,
                 cli_help: str = "", readme: str = "", context_pack: str = "",
                 max_retries: int = 2, retry_backoff_s: float = 2.0,
                 system_override: Optional[str] = None,
                 user_message_fn=None, reply_parser=None):
        self.api_key = api_key
        self.model_id = model_id
        self.url = url
        self.timeout_s = timeout_s
        self.cli_help = cli_help
        self.readme = readme
        self.context_pack = context_pack
        self._max_retries = max_retries
        self._retry_backoff_s = retry_backoff_s
        # CLI default: assemble from --help/README/context. GUI passes a
        # precomputed system_override + its own message/parse fns.
        self._system = system_override if system_override is not None \
            else _system_content(cli_help, readme, context_pack)
        self._user_message_fn = user_message_fn or _build_user_message
        self._reply_parser = reply_parser or _parse_reply
        self.last_cost_usd = 0.0

    def next_command(self, journey, step, observations) -> Dict[str, Any]:
        self.last_cost_usd = 0.0
        payload = {
            "model": self.model_id,
            "messages": [
                {"role": "system", "content": self._system},
                {"role": "user",
                 "content": self._user_message_fn(journey, step, observations)},
            ],
            "temperature": 0,
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.url, data=data, method="POST",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                # OpenRouter attribution headers (optional but recommended).
                "HTTP-Referer": "https://github.com/Lupus/izba",
                "X-Title": "izba-dogfood",
            },
        )
        # Cheap OpenRouter tiers are flaky (transient 429/5xx/timeouts). Retry a
        # few times with linear backoff before giving up — a single blip should
        # not silently end an otherwise-good journey. Report-only on exhaustion.
        body = None
        for attempt in range(self._max_retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                    body = json.loads(resp.read().decode("utf-8"))
                break
            except (urllib.error.URLError, ValueError, OSError):
                if attempt >= self._max_retries:
                    return {"done": True}
                time.sleep(self._retry_backoff_s * (attempt + 1))
        if body is None:
            return {"done": True}

        self.last_cost_usd = self._estimate_cost(body)
        try:
            content = body["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            return {"done": True}
        return self._reply_parser(content or "")

    @staticmethod
    def _estimate_cost(body: Dict[str, Any]) -> float:
        """Approximate USD from the OpenRouter ``usage`` block.

        Prefers an explicit cost if OpenRouter returns one; otherwise estimates
        from total tokens at ``APPROX_USD_PER_1M_TOKENS``. Approximate — used only
        to drive the budget cap, never as a billing figure.
        """
        usage = body.get("usage") or {}
        cost = usage.get("cost")
        if isinstance(cost, (int, float)):
            return float(cost)
        total = usage.get("total_tokens")
        if not isinstance(total, (int, float)):
            prompt = usage.get("prompt_tokens") or 0
            completion = usage.get("completion_tokens") or 0
            total = prompt + completion
        return float(total) / 1_000_000.0 * APPROX_USD_PER_1M_TOKENS
