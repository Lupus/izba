# hack/dogfood/gui/gui_model.py
"""The GUI Actor: same OpenRouter transport as the CLI model, but a UI-action
system prompt + a marks-based user message + a {click|fill|...} reply parser.

Fair-test: the prompt and message expose only what a user perceives — the
rendered accessibility marks. No source/spec/testid knowledge."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from model import OpenRouterModel  # noqa: E402  (sibling module on sys.path)

GUI_SYSTEM_PROMPT = (
    "You are the Actor in an automated GUI dogfooding loop: a person using the "
    "izba desktop app (a tool that runs per-project microVM sandboxes). You are "
    "given ONE user-journey step (an intent and its expected outcome) and the "
    "current screen as an accessibility list of interactive elements, each line "
    "'[@ref] role \"name\"'. Decide the SINGLE next UI action. Respond with ONLY "
    "a JSON object, no prose, one of:\n"
    '  {"click": "@e2"}                 click the element with that ref\n'
    '  {"fill": "@e3", "text": "web"}   type text into that field\n'
    '  {"press": "Enter"}               press a key\n'
    '  {"select": "@e9", "option": "x"} choose an option in a dropdown\n'
    '  {"read": true}                   re-read the screen (re-snapshot)\n'
    '  {"done": true}                   the step is satisfied (or cannot proceed)\n'
    "Only reference refs that appear in the current screen. If the screen does "
    "not offer a way to do the step, reply {\"done\": true} — do not invent refs. "
    "Prefer the smallest action that makes progress. Do not wrap the JSON in "
    "markdown."
)

_JSON_OBJ_RE = re.compile(r"\{.*?\}", re.DOTALL)
_KEYS = ("click", "fill", "press", "select", "read", "done")


def parse_gui_reply(content: str) -> Dict[str, Any]:
    content = (content or "").strip()
    obj = None
    try:
        obj = json.loads(content)
    except ValueError:
        m = _JSON_OBJ_RE.search(content)
        if m:
            try:
                obj = json.loads(m.group(0))
            except ValueError:
                obj = None
    if isinstance(obj, dict) and any(k in obj for k in _KEYS):
        return obj
    return {"done": True}


def build_gui_user_message(journey: Dict[str, Any], step: Dict[str, Any],
                           observations: List[Dict[str, Any]]) -> str:
    obs_lines = []
    for o in observations[-4:]:  # keep context small + cheap
        obs_lines.append(
            f"- did `{o.get('action', '')}`; screen now:\n{(o.get('marks') or '')[-1500:]}"
        )
    obs = "\n".join(obs_lines) if obs_lines else "(no actions yet)"
    return (
        f"Journey: {journey.get('journey_id', '')}\n"
        f"Step intent: {step.get('intent', '')}\n"
        f"Expected outcome: {step.get('expect', '')}\n"
        f"Recent actions + current screen:\n{obs}\n\n"
        "Next action JSON:"
    )


def _gui_system(app_guide: str = "", readme: str = "") -> str:
    parts = [GUI_SYSTEM_PROMPT]
    if app_guide.strip():
        parts.append("=== app guide (your environment) ===\n" + app_guide.strip())
    if readme.strip():
        parts.append("=== README (product documentation) ===\n" + readme.strip())
    return "\n\n".join(parts)


def build_gui_model(api_key: str, model_id: str, app_guide: str = "",
                    readme: str = "") -> OpenRouterModel:
    return OpenRouterModel(
        api_key, model_id,
        system_override=_gui_system(app_guide, readme),
        user_message_fn=build_gui_user_message,
        reply_parser=parse_gui_reply,
    )
