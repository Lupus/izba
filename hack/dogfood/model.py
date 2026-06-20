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
import urllib.error
import urllib.request
from typing import Any, Dict, List

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

# Approximate blended price for the cheap OpenRouter tier, in USD per 1M tokens.
# Deliberately conservative (rounds the estimate UP) so the budget cap trips
# early rather than late. Real per-model prices vary; this is only a guardrail
# estimate, not billing — actual cost is whatever OpenRouter charges.
APPROX_USD_PER_1M_TOKENS = 1.0

SYSTEM_PROMPT = (
    "You are the Actor in an automated izba dogfooding loop. izba is a CLI that "
    "runs per-project microVM sandboxes for AI coding agents. You are given ONE "
    "user-journey step (an intent and its expected outcome) plus the observations "
    "from the commands run so far. Decide the SINGLE next concrete shell command "
    "to advance this step — it should normally start with `izba`. "
    "Respond with ONLY a JSON object, no prose, in one of these two forms:\n"
    '  {"command": "izba ..."}   to run the next command\n'
    '  {"done": true}            when the step is satisfied (or cannot proceed).\n'
    "Never repeat a command that already ran with the same result. Prefer the "
    "smallest command that makes progress. Do not wrap the JSON in markdown."
)

def _system_content(cli_help: str = "") -> str:
    """System prompt, optionally seeded with the real `izba --help` surface so the
    Actor uses documented subcommands instead of guessing (start/init/list/...)."""
    if not (cli_help or "").strip():
        return SYSTEM_PROMPT
    return (
        SYSTEM_PROMPT
        + "\n\nUse ONLY the subcommands and flags documented in the `izba --help` "
        "output below — do NOT invent commands (there is no `start`, `init`, "
        "`list`, ...). Note exec/run take the guest command after `--` "
        "(e.g. `izba run -- uname -s`). If a step cannot be done with the "
        'documented surface, reply {"done": true}.\n\n'
        "=== izba help ===\n" + cli_help.strip()
    )


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
                 cli_help: str = ""):
        self.api_key = api_key
        self.model_id = model_id
        self.url = url
        self.timeout_s = timeout_s
        self.cli_help = cli_help
        self.last_cost_usd = 0.0

    def next_command(self, journey, step, observations) -> Dict[str, Any]:
        self.last_cost_usd = 0.0
        payload = {
            "model": self.model_id,
            "messages": [
                {"role": "system", "content": _system_content(self.cli_help)},
                {"role": "user",
                 "content": _build_user_message(journey, step, observations)},
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
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, ValueError, OSError):
            # Infra error: report-only -> signal done so the loop moves on.
            return {"done": True}

        self.last_cost_usd = self._estimate_cost(body)
        try:
            content = body["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            return {"done": True}
        return _parse_reply(content or "")

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
