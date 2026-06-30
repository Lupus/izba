# GUI Dogfooding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the LLM-dogfooding swarm to drive the Tauri app like a real user — cheap-LLM Actor → `agent-browser` (set-of-marks a11y refs) → real React frontend in headless Chromium → a headless Rust bridge sidecar reusing the app's real command/view/daemon logic → real microVMs — gated by daemon-truth + new GUI oracles, in CI, report-only.

**Architecture:** Reuse the 3-phase pipeline; swap only Phase-2's act/observe layer. A `tungstenite` WS sidecar (`izba-app` `bin/headless`) exposes `app_lib::dispatch(cmd,args)` over WebSocket; an in-page `real-bridge.js` forwards `__TAURI_INTERNALS__.invoke` to it and fires Tauri events back. The GUI Actor loop (`run_gui_journeys.py`) mirrors `run_journeys.py`, maps each browser action into the existing `Action` shape (so `reconcile_seq_oracle`/`capture_state_evidence` work unchanged against the shared `IZBA_DATA_DIR`), and adds four GUI oracles.

**Tech Stack:** Python 3 (stdlib only; `urllib`, `http.server`, `subprocess`), Rust (`tungstenite` sync WS, existing `izba-app`/`izba-core`), JS (vanilla in-page bridge), `agent-browser` v0.31.1 (Apache-2.0 CDP driver), GitHub Actions + KVM.

## Global Constraints

- **Spec:** `docs/superpowers/specs/2026-06-30-gui-dogfooding-design.md` — read it; this plan implements its §9 walking skeleton.
- **`agent-browser` pinned to `v0.31.1`**; never use its `chat` subcommand or `AI_GATEWAY_API_KEY` (that path embeds an external LLM).
- **Fair-test boundary:** the GUI Actor sees only rendered UI (a11y marks + visible text) + README + an app user-guide. Never component names, source, spec, or `data-testid`s.
- **Report-only:** any driver/subprocess/model error is logged; the loop never raises; a schema-valid trajectory bundle is always written; exit 0 regardless of findings.
- **Caps are mandatory:** `--max-turns`, `--step-cap`, `--max-usd`, `--action-timeout-s`, per-step loop-dedup.
- **Short paths:** per-journey `IZBA_DATA_DIR` must stay short (~108-byte `sun_path` limit; izba#71) — reuse `run_journeys._journey_data_dir`.
- **Python = stdlib only** (matches existing `hack/dogfood/`). No pip deps in the runner. `agent-browser` and the browser are external binaries.
- **Coverage:** `hack/dogfood/**` + `hack/**/*.py` are already in `sonar.coverage.exclusions`. The Rust sidecar bin + `real-bridge.js` must be added to that exclusion (Task 14); `#[mutants::skip]` the WS-loop glue with a one-line reason (`#[cfg_attr(test, mutants::skip)]` style per `CONTRIBUTING.md`).
- **Pure helpers stay covered + mutation-gated:** snapshot parsing, action mapping, the four GUI oracles, and `dispatch` (via `fake.rs`) get real unit tests.
- **TDD, conventional commits, frequent commits.** Run `python3 -m pytest hack/dogfood -q` for Python; `cd app/src-tauri && cargo test` for Rust.

---

## Phase 0 — Schema (both subsystems consume these)

### Task 1: Add `modality` to the journeys schema

**Files:**
- Modify: `hack/dogfood/schema/journeys.schema.json` (the `journey` definition `properties`)
- Test: `hack/dogfood/test_schema_gui.py` (new)

**Interfaces:**
- Produces: journeys may carry `"modality": "cli" | "gui"` (absent ⇒ `"cli"`). Consumed by Task 6 (`run_gui_journeys` selects `modality == "gui"`) and Task 11 (the GUI journeys file).

- [ ] **Step 1: Write the failing test**

```python
# hack/dogfood/test_schema_gui.py
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name):
    with open(os.path.join(HERE, "schema", name)) as f:
        return json.load(f)


def test_journey_allows_modality_enum():
    schema = _load("journeys.schema.json")
    modality = schema["definitions"]["journey"]["properties"]["modality"]
    assert modality["enum"] == ["cli", "gui"]


def test_journey_modality_is_optional():
    # modality is NOT in the journey's required list (absent ⇒ cli).
    schema = _load("journeys.schema.json")
    assert "modality" not in schema["definitions"]["journey"]["required"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest hack/dogfood/test_schema_gui.py -q`
Expected: FAIL — `KeyError: 'modality'`.

- [ ] **Step 3: Add the property**

In `hack/dogfood/schema/journeys.schema.json`, inside `definitions.journey.properties`, add (after `"source"`):

```json
        "modality": {
          "type": "string",
          "enum": ["cli", "gui"],
          "description": "Action surface this journey runs against. 'cli' (default) = izba shell commands via run_journeys.py; 'gui' = the Tauri app driven through a browser via run_gui_journeys.py. Absent ⇒ treated as 'cli'."
        },
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest hack/dogfood/test_schema_gui.py -q`
Expected: PASS (2 passed).

- [ ] **Step 5: Commit**

```bash
git add hack/dogfood/schema/journeys.schema.json hack/dogfood/test_schema_gui.py
git commit -m "feat(dogfood): add modality field to journeys schema"
```

### Task 2: Extend the trajectory schema for GUI candidates + actions

**Files:**
- Modify: `hack/dogfood/schema/trajectory.schema.json` (`candidate.kind` enum + `action` properties)
- Test: `hack/dogfood/test_schema_gui.py` (append)

**Interfaces:**
- Produces: `candidate.kind` additionally accepts `console | ui_daemon_diff | silent_failure | dom_expect`; `action` additionally accepts optional `snapshot` (string), `console_errors` (array of string), `screenshot_ref` (string). Consumed by Tasks 5–6.

- [ ] **Step 1: Write the failing test (append to `test_schema_gui.py`)**

```python
def test_candidate_kind_includes_gui_oracles():
    schema = _load("trajectory.schema.json")
    enum = schema["definitions"]["candidate"]["properties"]["kind"]["enum"]
    for k in ("functional", "latency", "implicit", "reconcile_seq",
              "console", "ui_daemon_diff", "silent_failure", "dom_expect"):
        assert k in enum, k


def test_action_allows_optional_gui_fields():
    schema = _load("trajectory.schema.json")
    props = schema["definitions"]["action"]["properties"]
    for k in ("snapshot", "console_errors", "screenshot_ref"):
        assert k in props, k
    # GUI fields are optional — required list is unchanged (CLI fields only).
    assert "snapshot" not in schema["definitions"]["action"]["required"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest hack/dogfood/test_schema_gui.py -q`
Expected: FAIL on the new asserts.

- [ ] **Step 3: Edit the schema**

In `hack/dogfood/schema/trajectory.schema.json`:

(a) Replace the `candidate.kind` enum:

```json
        "kind": {
          "type": "string",
          "enum": ["functional", "latency", "implicit", "reconcile_seq", "console", "ui_daemon_diff", "silent_failure", "dom_expect"],
          "description": "Which oracle produced the candidate. CLI oracles: functional/latency/implicit/reconcile_seq. GUI oracles: console (uncaught JS error / rejection), ui_daemon_diff (UI state disagrees with daemon truth), silent_failure (invoke rejected with no visible error surface), dom_expect (user-observable expectation absent from the snapshot)."
        },
```

(b) In `definitions.action.properties`, after `"reconcile"`, add:

```json
        "snapshot": { "type": "string", "description": "GUI only: the rendered accessibility set-of-marks the Actor saw after this action (role + name + @ref lines), trimmed. Empty for CLI actions." },
        "console_errors": { "type": "array", "items": { "type": "string" }, "description": "GUI only: uncaught JS errors / unhandled rejections collected by the in-page bridge during this action." },
        "screenshot_ref": { "type": "string", "description": "GUI only: artifact-relative path of an annotated screenshot captured on failure (for the Phase-3 skeptic). Absent on success." },
```

(Note: `action` keeps `additionalProperties: false`; GUI actions still populate the CLI-required fields — see Task 6's mapping.)

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest hack/dogfood/test_schema_gui.py -q`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
git add hack/dogfood/schema/trajectory.schema.json hack/dogfood/test_schema_gui.py
git commit -m "feat(dogfood): extend trajectory schema with GUI oracle kinds + action fields"
```

---

## Phase 1 — Python GUI substrate (testable standalone with fakes; no Rust, no VMs)

### Task 3: `gui/driver.py` — snapshot parsing, action mapping, FakeDriver + AgentBrowserDriver

**Files:**
- Create: `hack/dogfood/gui/__init__.py` (empty)
- Create: `hack/dogfood/gui/driver.py`
- Test: `hack/dogfood/gui/test_driver.py`

**Interfaces:**
- Produces:
  - `@dataclass Mark{ ref:str, role:str, name:str }`
  - `parse_snapshot(raw: str) -> List[Mark]` — accepts agent-browser `snapshot --json` JSON **or** the aria-snapshot text form (`- button "Save" [ref=e2]`). Refs normalized to `@eN`.
  - `render_marks(marks: List[Mark], cap_chars: int = 4000) -> str` — `"[@e2] button \"Save\""` lines, char-capped.
  - `action_to_argv(reply: dict) -> Optional[List[str]]` — maps `{click}|{fill}|{press}|{select}|{read}` to an `agent-browser` argv; `None` for `{read}`/`{done}`/unknown.
  - `@dataclass ActResult{ exit_code:int, stdout:str, stderr:str, latency_ms:int }`
  - class `FakeDriver(snapshots: List[str], errors: List[str] = [], invoke_log: List[dict] = [])` with `open/snapshot/act/read_console_errors/read_invoke_log/screenshot/close`; records `.actions`.
  - class `AgentBrowserDriver(bin: str, ws_port: int, http_port: int, timeout_s: float)` — same interface, shells out to `agent-browser ... --json`; reads console/invoke logs via `eval`.

- [ ] **Step 1: Write the failing test**

```python
# hack/dogfood/gui/test_driver.py
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from gui.driver import parse_snapshot, render_marks, action_to_argv, Mark


def test_parse_snapshot_text_form():
    raw = '- heading "Sandboxes" [ref=e1] [level=1]\n- button "Create sandbox" [ref=e2]\n- textbox "Name" [ref=e3]'
    marks = parse_snapshot(raw)
    assert marks == [
        Mark(ref="@e1", role="heading", name="Sandboxes"),
        Mark(ref="@e2", role="button", name="Create sandbox"),
        Mark(ref="@e3", role="textbox", name="Name"),
    ]


def test_parse_snapshot_json_form():
    raw = '{"elements":[{"ref":"e2","role":"button","name":"Create sandbox"}]}'
    assert parse_snapshot(raw) == [Mark(ref="@e2", role="button", name="Create sandbox")]


def test_parse_snapshot_garbage_is_empty():
    assert parse_snapshot("not a snapshot") == []


def test_render_marks_caps_chars():
    marks = [Mark(ref=f"@e{i}", role="button", name="x" * 50) for i in range(100)]
    out = render_marks(marks, cap_chars=200)
    assert len(out) <= 200
    assert out.startswith('[@e0] button "')


def test_action_to_argv_click_and_fill():
    assert action_to_argv({"click": "@e2"}) == ["click", "@e2"]
    assert action_to_argv({"fill": "@e3", "text": "web"}) == ["fill", "@e3", "web"]
    assert action_to_argv({"press": "Enter"}) == ["press", "Enter"]
    assert action_to_argv({"select": "@e9", "option": "alpine"}) == ["select", "@e9", "alpine"]


def test_action_to_argv_read_and_done_are_none():
    assert action_to_argv({"read": True}) is None
    assert action_to_argv({"done": True}) is None
    assert action_to_argv({"bogus": 1}) is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest hack/dogfood/gui/test_driver.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'gui'` or import error.

- [ ] **Step 3: Implement `driver.py`**

```python
# hack/dogfood/gui/driver.py
"""The browser-driver layer for the GUI dogfood runner.

Wraps `vercel-labs/agent-browser` (a CDP driver, called as a `--json`
subprocess) behind a tiny interface, plus a `FakeDriver` for offline tests.
Pure helpers (snapshot parsing, marks rendering, action mapping) are
unit-tested; the subprocess driver is exercised only in CI.
"""
from __future__ import annotations

import json
import re
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class Mark:
    ref: str   # normalized "@eN"
    role: str
    name: str


@dataclass
class ActResult:
    exit_code: int
    stdout: str
    stderr: str
    latency_ms: int


# `- button "Create sandbox" [ref=e2]` (aria-snapshot text form). The name is
# the first quoted run; trailing `[level=1]` etc. are ignored.
_ARIA_RE = re.compile(r'^\s*-\s+(?P<role>[a-zA-Z]+)\s+"(?P<name>(?:[^"\\]|\\.)*)"\s+\[ref=(?P<ref>e\d+)\]')


def _norm_ref(ref: str) -> str:
    return ref if ref.startswith("@") else "@" + ref


def parse_snapshot(raw: str) -> List[Mark]:
    """Parse an agent-browser snapshot (JSON or aria-text) into Marks.

    Best-effort: unparseable input yields []. JSON form expects
    {"elements":[{"ref","role","name"}, ...]} (refs may already carry '@')."""
    raw = (raw or "").strip()
    if not raw:
        return []
    # JSON form first (snapshot --json).
    if raw[0] in "{[":
        try:
            doc = json.loads(raw)
        except ValueError:
            doc = None
        if isinstance(doc, dict):
            els = doc.get("elements") or doc.get("snapshot") or []
        elif isinstance(doc, list):
            els = doc
        else:
            els = []
        out: List[Mark] = []
        for e in els:
            if not isinstance(e, dict):
                continue
            ref = e.get("ref")
            if not ref:
                continue
            out.append(Mark(ref=_norm_ref(str(ref)), role=str(e.get("role", "")),
                            name=str(e.get("name", ""))))
        if out:
            return out
        # fall through to text parsing if JSON had no usable elements
    marks: List[Mark] = []
    for line in raw.splitlines():
        m = _ARIA_RE.match(line)
        if m:
            marks.append(Mark(ref=_norm_ref(m.group("ref")), role=m.group("role"),
                              name=m.group("name")))
    return marks


def render_marks(marks: List[Mark], cap_chars: int = 4000) -> str:
    """One `[@ref] role "name"` line per mark, total capped at cap_chars."""
    lines: List[str] = []
    total = 0
    for mk in marks:
        line = f'[{mk.ref}] {mk.role} "{mk.name}"'
        if total + len(line) + 1 > cap_chars:
            break
        lines.append(line)
        total += len(line) + 1
    return "\n".join(lines)


def action_to_argv(reply: Dict[str, Any]) -> Optional[List[str]]:
    """Map an Actor reply to an agent-browser argv. None ⇒ no driver action
    (read/done/unknown)."""
    if not isinstance(reply, dict):
        return None
    if "click" in reply:
        return ["click", str(reply["click"])]
    if "fill" in reply:
        return ["fill", str(reply["fill"]), str(reply.get("text", ""))]
    if "press" in reply:
        return ["press", str(reply["press"])]
    if "select" in reply:
        return ["select", str(reply["select"]), str(reply.get("option", ""))]
    return None


class FakeDriver:
    """Offline driver for tests: pops scripted snapshots; records actions."""

    def __init__(self, snapshots: Optional[List[str]] = None,
                 errors: Optional[List[str]] = None,
                 invoke_log: Optional[List[Dict[str, Any]]] = None):
        self._snaps = list(snapshots or [])
        self._errors = list(errors or [])
        self._invoke_log = list(invoke_log or [])
        self.actions: List[List[str]] = []
        self.opened: Optional[str] = None
        self.closed = False

    def open(self, url: str) -> None:
        self.opened = url

    def snapshot(self) -> List[Mark]:
        raw = self._snaps.pop(0) if self._snaps else ""
        return parse_snapshot(raw)

    def act(self, argv: List[str]) -> ActResult:
        self.actions.append(argv)
        return ActResult(exit_code=0, stdout="", stderr="", latency_ms=1)

    def read_console_errors(self) -> List[str]:
        return list(self._errors)

    def read_invoke_log(self) -> List[Dict[str, Any]]:
        return list(self._invoke_log)

    def screenshot(self, path: str) -> None:
        pass

    def close(self) -> None:
        self.closed = True


class AgentBrowserDriver:
    """Drives a headless browser via `agent-browser <cmd> --json`. CI-only.

    Reads the in-page bridge's error/invoke logs (window.__DF_CONSOLE_ERRORS__ /
    window.__DF_INVOKE_LOG__) via `agent-browser eval`, so it does not depend on
    any agent-browser console subcommand. Report-only: a failed subprocess
    returns a non-zero ActResult rather than raising."""

    def __init__(self, bin: str, http_port: int, ws_port: int, timeout_s: float = 30.0):
        self.bin = bin
        self.http_port = http_port
        self.ws_port = ws_port
        self.timeout_s = timeout_s

    def _run(self, args: List[str]) -> ActResult:
        t0 = time.monotonic()
        try:
            p = subprocess.run([self.bin, *args, "--json"], capture_output=True,
                               text=True, timeout=self.timeout_s)
            code, out, err = p.returncode, p.stdout or "", p.stderr or ""
        except (OSError, subprocess.SubprocessError) as e:
            code, out, err = 124, "", repr(e)
        return ActResult(exit_code=code, stdout=out, stderr=err,
                         latency_ms=int((time.monotonic() - t0) * 1000))

    def open(self, url: str) -> None:
        self._run(["open", url])

    def snapshot(self) -> List[Mark]:
        return parse_snapshot(self._run(["snapshot", "-i"]).stdout)

    def act(self, argv: List[str]) -> ActResult:
        return self._run(argv)

    def _eval_json(self, expr: str) -> Any:
        out = self._run(["eval", expr]).stdout.strip()
        # agent-browser --json wraps results; tolerate either a bare JSON value
        # or {"result": <value-or-json-string>}.
        try:
            doc = json.loads(out)
        except ValueError:
            return None
        val = doc.get("result", doc) if isinstance(doc, dict) else doc
        if isinstance(val, str):
            try:
                return json.loads(val)
            except ValueError:
                return val
        return val

    def read_console_errors(self) -> List[str]:
        v = self._eval_json("JSON.stringify(window.__DF_CONSOLE_ERRORS__||[])")
        return [str(x) for x in v] if isinstance(v, list) else []

    def read_invoke_log(self) -> List[Dict[str, Any]]:
        v = self._eval_json("JSON.stringify(window.__DF_INVOKE_LOG__||[])")
        return [x for x in v if isinstance(x, dict)] if isinstance(v, list) else []

    def screenshot(self, path: str) -> None:
        self._run(["screenshot", path, "--annotate"])

    def close(self) -> None:
        self._run(["close"])
```

> Verify at first CI run: the exact `agent-browser snapshot --json` payload shape and the `eval` result wrapping. `parse_snapshot`/`_eval_json` already tolerate both the JSON and text forms; adjust the `els`/`result` key names here if the real payload differs.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest hack/dogfood/gui/test_driver.py -q`
Expected: PASS (6 passed).

- [ ] **Step 5: Commit**

```bash
git add hack/dogfood/gui/__init__.py hack/dogfood/gui/driver.py hack/dogfood/gui/test_driver.py
git commit -m "feat(dogfood): add GUI browser-driver layer (agent-browser wrapper + FakeDriver)"
```

### Task 4: `gui/gui_model.py` — the GUI Actor (prompt + reply parsing), reusing the OpenRouter transport

**Files:**
- Modify: `hack/dogfood/model.py` (parametrize `OpenRouterModel` with an optional precomputed system prompt + user-message builder + reply parser — default = current CLI behavior)
- Create: `hack/dogfood/gui/gui_model.py`
- Test: `hack/dogfood/gui/test_gui_model.py`

**Interfaces:**
- Consumes: `model.OpenRouterModel`, `model.FakeModel`.
- Produces:
  - `gui_model.GUI_SYSTEM_PROMPT: str`
  - `gui_model.build_gui_user_message(journey, step, observations) -> str`
  - `gui_model.parse_gui_reply(content: str) -> dict` — extracts one of `{click}|{fill}|{press}|{select}|{read}|{done}`; `{"done": True}` on anything unparseable.
  - `gui_model.build_gui_model(api_key, model_id, app_guide="", readme="") -> OpenRouterModel`
  - `FakeModel` is reused unchanged for GUI (it returns scripted dicts).

- [ ] **Step 1: Write the failing test**

```python
# hack/dogfood/gui/test_gui_model.py
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from gui.gui_model import parse_gui_reply, build_gui_user_message, GUI_SYSTEM_PROMPT


def test_parse_gui_reply_variants():
    assert parse_gui_reply('{"click": "@e2"}') == {"click": "@e2"}
    assert parse_gui_reply('{"fill": "@e3", "text": "web"}') == {"fill": "@e3", "text": "web"}
    assert parse_gui_reply('noise {"press":"Enter"} tail') == {"press": "Enter"}
    assert parse_gui_reply('{"done": true}') == {"done": True}


def test_parse_gui_reply_garbage_is_done():
    assert parse_gui_reply("totally not json") == {"done": True}
    assert parse_gui_reply('{"unknown": 1}') == {"done": True}


def test_user_message_includes_marks_and_intent():
    msg = build_gui_user_message(
        {"journey_id": "j1"},
        {"intent": "create a sandbox", "expect": "it appears in the list"},
        [{"action": "click @e2", "marks": '[@e9] button "Create"'}],
    )
    assert "create a sandbox" in msg
    assert "it appears in the list" in msg
    assert "@e9" in msg


def test_system_prompt_is_ui_actor_and_leaks_nothing_internal():
    assert "click" in GUI_SYSTEM_PROMPT.lower()
    # fair-test: the prompt must not name source/spec/testid scaffolding.
    for banned in ("data-testid", "src/components", "spec"):
        assert banned not in GUI_SYSTEM_PROMPT.lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest hack/dogfood/gui/test_gui_model.py -q`
Expected: FAIL — module not found.

- [ ] **Step 3a: Parametrize `OpenRouterModel` in `model.py`**

In `hack/dogfood/model.py`, change `OpenRouterModel.__init__` to accept optional overrides, defaulting to current behavior. Replace the `__init__` signature + the two body lines that build `self._system` / call `_build_user_message`:

```python
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
```

Then in `next_command`, change the two call sites:

```python
                 "content": self._user_message_fn(journey, step, observations)},
```
and
```python
        return self._reply_parser(content or "")
```

Add `Optional` to the `typing` import line if not present (it imports `Any, Dict, List` — add `Optional`).

- [ ] **Step 3b: Implement `gui/gui_model.py`**

```python
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
```

- [ ] **Step 4: Run tests (GUI + ensure CLI model tests still pass)**

Run: `python3 -m pytest hack/dogfood/gui/test_gui_model.py hack/dogfood/test_runner.py -q`
Expected: PASS (GUI model tests + unchanged CLI runner/model tests green).

- [ ] **Step 5: Commit**

```bash
git add hack/dogfood/model.py hack/dogfood/gui/gui_model.py hack/dogfood/gui/test_gui_model.py
git commit -m "feat(dogfood): add GUI Actor model (UI prompt + reply parser) reusing OpenRouter transport"
```

### Task 5: `gui/gui_oracles.py` — the four GUI candidate producers

**Files:**
- Create: `hack/dogfood/gui/gui_oracles.py`
- Test: `hack/dogfood/gui/test_gui_oracles.py`

**Interfaces:**
- Consumes: `oracles.Candidate`.
- Produces (all `-> List[Candidate]`, all pure):
  - `console_oracle(console_errors: List[str], ref: dict) -> List[Candidate]`
  - `dom_expect_oracle(expect: str, marks_text: str, ref: dict) -> List[Candidate]`
  - `silent_failure_oracle(invoke_log: List[dict], marks_text: str, ref: dict) -> List[Candidate]`
  - `ui_daemon_diff_oracle(marks_text: str, state_evidence: dict, ref: dict) -> List[Candidate]`
  - helper `expectation_keywords(expect: str) -> List[str]` (lowercased significant tokens).
- `invoke_log` entry shape (from `real-bridge.js`, Task 8): `{"cmd": str, "ok": bool, "error": str}`.

- [ ] **Step 1: Write the failing test**

```python
# hack/dogfood/gui/test_gui_oracles.py
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from gui.gui_oracles import (console_oracle, dom_expect_oracle,
                             silent_failure_oracle, ui_daemon_diff_oracle)

REF = {"journey_id": "j1", "action_index": 0}


def test_console_oracle_flags_errors():
    cs = console_oracle(["TypeError: x is undefined"], REF)
    assert len(cs) == 1 and cs[0].kind == "console"
    assert console_oracle([], REF) == []


def test_dom_expect_oracle_passes_when_keyword_present():
    assert dom_expect_oracle("the sandbox web appears in the list",
                             '[@e1] row "web running"', REF) == []


def test_dom_expect_oracle_flags_when_absent():
    cs = dom_expect_oracle("the sandbox web appears in the list",
                           '[@e1] heading "Sandboxes"', REF)
    assert len(cs) == 1 and cs[0].kind == "dom_expect"


def test_silent_failure_oracle_flags_rejected_invoke_with_no_error_surface():
    log = [{"cmd": "create", "ok": False, "error": "boom"}]
    cs = silent_failure_oracle(log, '[@e1] heading "Sandboxes"', REF)
    assert len(cs) == 1 and cs[0].kind == "silent_failure"


def test_silent_failure_oracle_quiet_when_error_is_shown():
    log = [{"cmd": "create", "ok": False, "error": "boom"}]
    assert silent_failure_oracle(log, '[@e1] alert "boom"', REF) == []


def test_ui_daemon_diff_flags_sandbox_missing_from_ui():
    ev = {"sandboxes": ["web"]}
    cs = ui_daemon_diff_oracle('[@e1] heading "Sandboxes"', ev, REF)
    assert len(cs) == 1 and cs[0].kind == "ui_daemon_diff"


def test_ui_daemon_diff_quiet_when_ui_shows_sandbox():
    ev = {"sandboxes": ["web"]}
    assert ui_daemon_diff_oracle('[@e1] row "web running"', ev, REF) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest hack/dogfood/gui/test_gui_oracles.py -q`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `gui_oracles.py`**

```python
# hack/dogfood/gui/gui_oracles.py
"""GUI-specific deterministic oracles. Each returns oracle Candidates (the same
dataclass the CLI oracles use). Daemon-truth oracles (reconcile_seq,
capture_state_evidence) are reused from oracles.py unchanged — the daemon is
real and reachable via the izba binary against the shared IZBA_DATA_DIR."""
from __future__ import annotations

import re
from typing import Any, Dict, List

from oracles import Candidate  # noqa: E402

_STOP = {"the", "a", "an", "is", "are", "in", "to", "of", "and", "it", "its",
         "with", "that", "this", "appears", "shows", "should", "be", "as",
         "for", "on", "list", "view", "screen"}
_WORD_RE = re.compile(r"[a-zA-Z0-9_-]{3,}")


def expectation_keywords(expect: str) -> List[str]:
    """Significant lowercased tokens of an expectation (stopwords dropped)."""
    return [w for w in (m.group(0).lower() for m in _WORD_RE.finditer(expect or ""))
            if w not in _STOP]


def console_oracle(console_errors: List[str], ref: Dict[str, Any]) -> List[Candidate]:
    out: List[Candidate] = []
    for e in console_errors or []:
        out.append(Candidate(
            kind="console",
            detail=f"uncaught JS error / rejection during the journey: {e[:300]}",
            violated_expectation="the UI runs without uncaught JS errors",
            source="implicit UI contract", trajectory_ref=dict(ref)))
    return out


def dom_expect_oracle(expect: str, marks_text: str, ref: Dict[str, Any]) -> List[Candidate]:
    """If NONE of the expectation's significant keywords appears in the final
    screen, the user-observable outcome is missing. Conservative (needs zero
    overlap) to stay low-noise — the skeptic adjudicates borderline cases."""
    kws = expectation_keywords(expect)
    if not kws:
        return []
    hay = (marks_text or "").lower()
    if any(k in hay for k in kws):
        return []
    return [Candidate(
        kind="dom_expect",
        detail=f"none of {kws!r} present in the final screen",
        violated_expectation=expect, source="journey step",
        trajectory_ref=dict(ref))]


def silent_failure_oracle(invoke_log: List[Dict[str, Any]], marks_text: str,
                          ref: Dict[str, Any]) -> List[Candidate]:
    """A backend invoke that rejected but left no visible error surface (no
    'alert'/'error'/the error text) in the screen = the user wasn't told."""
    hay = (marks_text or "").lower()
    surfaced = ("alert" in hay) or ("error" in hay) or ("failed" in hay)
    out: List[Candidate] = []
    for e in invoke_log or []:
        if isinstance(e, dict) and e.get("ok") is False:
            msg = str(e.get("error", "")).lower()
            if surfaced or (msg and msg[:40] in hay):
                continue
            out.append(Candidate(
                kind="silent_failure",
                detail=f"invoke {e.get('cmd')!r} rejected ({e.get('error')!r}) "
                       f"with no visible error surface",
                violated_expectation="a failed action tells the user it failed",
                source="implicit UI contract", trajectory_ref=dict(ref)))
    return out


def ui_daemon_diff_oracle(marks_text: str, state_evidence: Dict[str, Any],
                          ref: Dict[str, Any]) -> List[Candidate]:
    """Differential: every sandbox the daemon reports must be visible in the
    final UI. A sandbox in daemon truth but absent from the screen = the UI
    lies about / drops real state."""
    hay = (marks_text or "").lower()
    out: List[Candidate] = []
    for name in (state_evidence or {}).get("sandboxes", []) or []:
        if str(name).lower() not in hay:
            out.append(Candidate(
                kind="ui_daemon_diff",
                detail=f"daemon reports sandbox {name!r} but it is absent from the UI",
                violated_expectation="the UI reflects the daemon's actual sandboxes",
                source="daemon state-evidence", trajectory_ref=dict(ref)))
    return out
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest hack/dogfood/gui/test_gui_oracles.py -q`
Expected: PASS (7 passed).

- [ ] **Step 5: Commit**

```bash
git add hack/dogfood/gui/gui_oracles.py hack/dogfood/gui/test_gui_oracles.py
git commit -m "feat(dogfood): add GUI oracles (console, dom-expect, silent-failure, ui-daemon-diff)"
```

### Task 6: `gui/run_gui_journeys.py` — the GUI Actor loop + trajectory writer

**Files:**
- Create: `hack/dogfood/gui/run_gui_journeys.py`
- Test: `hack/dogfood/gui/test_run_gui_journeys.py`

**Interfaces:**
- Consumes: `driver.{FakeDriver,AgentBrowserDriver,action_to_argv,render_marks}`, `gui_model.build_gui_model`, `model.FakeModel`, `oracles.{Candidate,reconcile_seq_oracle,latency_oracle,capture_state_evidence}`, `run_journeys.{select_shard,_journey_data_dir,BudgetExceeded}`, the GUI oracles.
- Produces: `run_gui_journey(model, driver, journey, *, izba_bin, data_dir, caps...) -> dict` (a journey_result matching `trajectory.schema.json` with GUI action fields), and a `main(argv)` CLI. Selects journeys with `modality == "gui"`.
- A GUI **action** is mapped into the existing `Action` shape: `command` = the action argv joined (e.g. `"click @e2"`), `exit_code` = driver exit, `stdout_tail` = the post-action marks, `stderr_tail` = "", `latency_ms` = action latency, `reconcile` = the `izba __reconcile --json` snapshot after the action; plus optional `snapshot`/`console_errors`/`screenshot_ref`.

- [ ] **Step 1: Write the failing test (fakes only — no browser, no daemon)**

```python
# hack/dogfood/gui/test_run_gui_journeys.py
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from gui.driver import FakeDriver
from gui.run_gui_journeys import run_gui_journey, select_gui_journeys
from model import FakeModel


def _reconcile(_bin, _dir, _t, env=None):
    return {"sandboxes": ["web"], "reconcile": {}, "per_sandbox": {}}


def test_select_gui_journeys_filters_modality():
    js = [{"journey_id": "a", "modality": "gui"}, {"journey_id": "b"},
          {"journey_id": "c", "modality": "cli"}]
    assert [j["journey_id"] for j in select_gui_journeys(js)] == ["a"]


def test_run_gui_journey_happy_path_records_actions_and_state(monkeypatch):
    # Actor: click create, then done.
    model = FakeModel([{"click": "@e2"}, {"done": True}])
    # screen before each snapshot: first the create button, then the new row.
    driver = FakeDriver(snapshots=['[@e2] button "Create"',
                                   '[@e1] row "web running"',
                                   '[@e1] row "web running"'])
    import gui.run_gui_journeys as rgj
    monkeypatch.setattr(rgj, "capture_state_evidence", _reconcile)
    monkeypatch.setattr(rgj, "_reconcile_snapshot", lambda *a, **k: {"violations": []})
    journey = {"journey_id": "j1", "modality": "gui",
               "steps": [{"intent": "create a sandbox web",
                          "expect": "the sandbox web appears in the list"}]}
    res = run_gui_journey(model, driver, journey, izba_bin="izba",
                          data_dir="/tmp/x", max_turns=8, step_cap=10,
                          action_timeout_s=5, latency_budget_ms=30000,
                          budget={"usd": 0.0}, max_usd=2.0)
    assert res["journey_id"] == "j1"
    assert driver.actions == [["click", "@e2"]]
    assert res["actions"][0]["command"] == "click @e2"
    # UI shows 'web', daemon shows 'web' ⇒ no ui_daemon_diff candidate.
    assert not [c for c in res["candidates"] if c["kind"] == "ui_daemon_diff"]


def test_run_gui_journey_flags_ui_daemon_diff(monkeypatch):
    model = FakeModel([{"done": True}])
    driver = FakeDriver(snapshots=['[@e1] heading "Sandboxes"',
                                   '[@e1] heading "Sandboxes"'])
    import gui.run_gui_journeys as rgj
    monkeypatch.setattr(rgj, "capture_state_evidence", _reconcile)
    monkeypatch.setattr(rgj, "_reconcile_snapshot", lambda *a, **k: {"violations": []})
    journey = {"journey_id": "j2", "modality": "gui",
               "steps": [{"intent": "look at the list", "expect": "web is listed"}]}
    res = run_gui_journey(model, driver, journey, izba_bin="izba",
                          data_dir="/tmp/x", max_turns=8, step_cap=10,
                          action_timeout_s=5, latency_budget_ms=30000,
                          budget={"usd": 0.0}, max_usd=2.0)
    kinds = {c["kind"] for c in res["candidates"]}
    assert "ui_daemon_diff" in kinds  # daemon has 'web', UI does not
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest hack/dogfood/gui/test_run_gui_journeys.py -q`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `run_gui_journeys.py`**

```python
# hack/dogfood/gui/run_gui_journeys.py
"""GUI dogfood Phase-2 runner: the Actor loop for the Tauri app, driven through
a browser via agent-browser, against a real daemon (the headless bridge
sidecar) and real microVMs.

Mirrors run_journeys.py: same caps, same report-only contract, same per-journey
data-dir isolation, same trajectory shape — only the act/observe primitives
differ. Daemon-truth oracles are reused unchanged: each browser action is
mapped into the existing Action dict, with `reconcile` = the izba __reconcile
snapshot after the action and a final capture_state_evidence pass."""
from __future__ import annotations

import argparse
import functools
import hashlib
import http.server
import json
import os
import socket
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from model import FakeModel  # noqa: E402
from oracles import (  # noqa: E402
    capture_state_evidence, latency_oracle, reconcile_seq_oracle,
)
from run_journeys import select_shard, _journey_data_dir, BudgetExceeded  # noqa: E402
from gui.driver import (  # noqa: E402
    AgentBrowserDriver, FakeDriver, action_to_argv, render_marks,
)
from gui.gui_model import build_gui_model  # noqa: E402
from gui.gui_oracles import (  # noqa: E402
    console_oracle, dom_expect_oracle, silent_failure_oracle, ui_daemon_diff_oracle,
)

DEFAULT_LATENCY_BUDGET_MS = 30_000


def log(msg: str) -> None:
    print(f"[dogfood-gui] {msg}", file=sys.stderr, flush=True)


def select_gui_journeys(journeys: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [j for j in journeys if j.get("modality") == "gui"]


def _reconcile_snapshot(izba_bin: str, data_dir: str, timeout_s: float,
                        env: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """`izba __reconcile --json` against the shared data dir → snapshot dict
    (always has a 'violations' key). Report-only: errors yield an empty snap."""
    run_env = dict(os.environ)
    if env:
        run_env.update(env)
    run_env["IZBA_DATA_DIR"] = data_dir
    try:
        p = subprocess.run([izba_bin, "__reconcile", "--json"], capture_output=True,
                           text=True, timeout=timeout_s, env=run_env)
        snap = json.loads(p.stdout or "{}")
    except (OSError, subprocess.SubprocessError, ValueError):
        snap = {}
    if "violations" not in snap:
        snap["violations"] = []
    return snap


def _action_dict(intent: str, command: str, res, marks_text: str,
                 reconcile: Dict[str, Any], console_errors: List[str],
                 screenshot_ref: str = "") -> Dict[str, Any]:
    """Map a GUI action into the trajectory Action shape (+ optional GUI fields)."""
    d = {
        "intent": intent,
        "command": command,
        "exit_code": int(getattr(res, "exit_code", 0)),
        "stdout_tail": marks_text[-4000:],
        "stderr_tail": (getattr(res, "stderr", "") or "")[-4000:],
        "latency_ms": int(getattr(res, "latency_ms", 0)),
        "reconcile": reconcile,
        "snapshot": marks_text[-4000:],
        "console_errors": list(console_errors or []),
    }
    if screenshot_ref:
        d["screenshot_ref"] = screenshot_ref
    return d


def _cmd_hash(journey_id: str, command: str) -> str:
    return hashlib.sha256(f"{journey_id}\0{command}".encode("utf-8")).hexdigest()


def run_gui_journey(model, driver, journey: Dict[str, Any], *, izba_bin: str,
                    data_dir: str, max_turns: int, step_cap: int,
                    action_timeout_s: float, latency_budget_ms: int,
                    budget: Dict[str, float], max_usd: float,
                    artifact_dir: str = "") -> Dict[str, Any]:
    """Run one GUI journey under all caps. Returns a journey_result dict."""
    journey_id = journey.get("journey_id", "")
    actions: List[Dict[str, Any]] = []
    candidates: List[Dict[str, Any]] = []
    turns = 0
    prev_reconcile: Optional[Dict[str, Any]] = None
    steps = journey.get("steps", []) or [{"intent": journey.get("rationale", ""),
                                          "expect": ""}]
    try:
        for step in steps:
            seen: set = set()
            obs: List[Dict[str, Any]] = []
            # Seed the Actor with the current screen.
            marks_text = render_marks(driver.snapshot())
            while True:
                if len(actions) >= step_cap:
                    log(f"{journey_id}: step-cap reached"); raise StopIteration
                if turns >= max_turns:
                    log(f"{journey_id}: max-turns reached"); raise StopIteration
                if budget["usd"] >= max_usd:
                    raise BudgetExceeded()
                turns += 1
                try:
                    reply = model.next_command(journey, step, obs)
                    budget["usd"] += float(getattr(model, "last_cost_usd", 0.0) or 0.0)
                except Exception as e:  # report-only
                    log(f"{journey_id}: model error: {e!r}"); break
                if not isinstance(reply, dict) or reply.get("done"):
                    break
                if reply.get("read"):
                    marks_text = render_marks(driver.snapshot())
                    obs.append({"action": "read", "marks": marks_text})
                    continue
                argv = action_to_argv(reply)
                if argv is None:
                    break
                command = " ".join(argv)
                h = _cmd_hash(journey_id, command)
                if h in seen:
                    log(f"{journey_id}: loop-dedup on {command!r}"); break
                seen.add(h)
                res = driver.act(argv)
                marks_text = render_marks(driver.snapshot())
                reconcile = _reconcile_snapshot(izba_bin, data_dir, action_timeout_s)
                console_errors = driver.read_console_errors()
                action_index = len(actions)
                ref = {"journey_id": journey_id, "action_index": action_index}
                actions.append(_action_dict(step.get("intent", ""), command, res,
                                            marks_text, reconcile, console_errors))
                obs.append({"action": command, "marks": marks_text})
                # Per-action oracles.
                from oracles import Action as _A
                act_obj = _A(intent=step.get("intent", ""), command=command,
                             exit_code=int(res.exit_code), stdout_tail=marks_text,
                             stderr_tail="", latency_ms=int(res.latency_ms),
                             reconcile=reconcile)
                found = (latency_oracle(act_obj, latency_budget_ms)
                         + console_oracle(console_errors, ref))
                if prev_reconcile is not None:
                    found += reconcile_seq_oracle(prev_reconcile, reconcile)
                for c in found:
                    cd = c.to_dict(); cd["trajectory_ref"] = ref
                    candidates.append(cd)
                prev_reconcile = reconcile
    except StopIteration:
        pass
    except BudgetExceeded:
        raise

    # End-of-journey oracles: daemon truth + UI-vs-daemon + dom-expect + silent-fail.
    try:
        state_evidence = capture_state_evidence(izba_bin, data_dir, action_timeout_s,
                                                env={"IZBA_DATA_DIR": data_dir})
    except Exception as e:  # report-only
        log(f"{journey_id}: state-evidence error: {e!r}")
        state_evidence = {"sandboxes": [], "reconcile": {}, "per_sandbox": {}}
    final_marks = render_marks(driver.snapshot())
    final_ref = {"journey_id": journey_id, "action_index": -1}
    invoke_log = driver.read_invoke_log()
    last_expect = (steps[-1].get("expect", "") if steps else "")
    end_found = (ui_daemon_diff_oracle(final_marks, state_evidence, final_ref)
                 + dom_expect_oracle(last_expect, final_marks, final_ref)
                 + silent_failure_oracle(invoke_log, final_marks, final_ref))
    # Capture an annotated screenshot only if the journey produced any candidate.
    if (candidates or end_found) and artifact_dir:
        shot = os.path.join(artifact_dir, f"{journey_id}.png")
        try:
            driver.screenshot(shot)
            for c in end_found:
                c.trajectory_ref = dict(final_ref)
        except Exception:
            shot = ""
    for c in end_found:
        cd = c.to_dict(); cd["trajectory_ref"] = dict(final_ref)
        candidates.append(cd)
    return {"journey_id": journey_id, "actions": actions, "candidates": candidates,
            "state_evidence": state_evidence}


# ---------- CI orchestration (static server + sidecar lifecycle) ----------

def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _serve_dir(directory: str, port: int) -> http.server.ThreadingHTTPServer:
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=directory)
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def _spawn_sidecar(sidecar_bin: str, data_dir: str, ws_port: int):
    env = dict(os.environ)
    env["IZBA_DATA_DIR"] = data_dir
    env["IZBA_DOGFOOD_WS_PORT"] = str(ws_port)
    return subprocess.Popen([sidecar_bin], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _wait_port(port: int, timeout_s: float = 15.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def build_model(args):
    if args.fake_model is not None:
        return FakeModel(json.loads(args.fake_model))
    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        raise SystemExit("OPENROUTER_API_KEY required (or pass --fake-model)")
    readme = _read_optional(args.readme)
    app_guide = _read_optional(args.app_guide)
    return build_gui_model(api_key, args.model, app_guide=app_guide, readme=readme)


def _read_optional(path: str) -> str:
    if not path:
        return ""
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return ""


def parse_args(argv):
    p = argparse.ArgumentParser(prog="run_gui_journeys.py")
    p.add_argument("--journeys", required=True)
    p.add_argument("--shard", type=int, default=0)
    p.add_argument("--shards", type=int, default=1)
    p.add_argument("--izba-bin", required=True)
    p.add_argument("--sidecar-bin", required=True)
    p.add_argument("--frontend-dir", required=True, help="built dogfood dist (with real-bridge.js)")
    p.add_argument("--agent-browser-bin", default="agent-browser")
    p.add_argument("--data-dir", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--artifact-dir", default="")
    p.add_argument("--model", default="google/gemini-2.5-flash")
    p.add_argument("--max-turns", type=int, default=14)
    p.add_argument("--max-usd", type=float, default=2.0)
    p.add_argument("--step-cap", type=int, default=20)
    p.add_argument("--action-timeout-s", type=float, default=30.0)
    p.add_argument("--latency-budget-ms", type=int, default=DEFAULT_LATENCY_BUDGET_MS)
    p.add_argument("--readme", default="README.md")
    p.add_argument("--app-guide", default="dogfood-app-guide.md")
    p.add_argument("--fake-model", default=None)
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    with open(args.journeys) as f:
        doc = json.load(f)
    feature = doc.get("feature", "")
    mine = select_shard(select_gui_journeys(doc.get("journeys", []) or []),
                        args.shard, args.shards)
    log(f"shard {args.shard}/{args.shards}: {len(mine)} gui journeys")
    os.makedirs(args.data_dir, exist_ok=True)
    if args.artifact_dir:
        os.makedirs(args.artifact_dir, exist_ok=True)
    model = build_model(args)

    http_port = _free_port()
    httpd = _serve_dir(args.frontend_dir, http_port)
    budget = {"usd": 0.0}
    results: List[Dict[str, Any]] = []
    try:
        for journey in mine:
            jid = journey.get("journey_id") or ""
            jdir = _journey_data_dir(args.data_dir, jid)
            os.makedirs(jdir, exist_ok=True)
            ws_port = _free_port()
            sidecar = _spawn_sidecar(args.sidecar_bin, jdir, ws_port)
            try:
                if not _wait_port(ws_port):
                    log(f"{jid}: sidecar did not come up on :{ws_port}; skipping")
                    results.append({"journey_id": jid, "actions": [], "candidates": []})
                    continue
                driver = AgentBrowserDriver(args.agent_browser_bin, http_port, ws_port,
                                            timeout_s=args.action_timeout_s)
                driver.open(f"http://127.0.0.1:{http_port}/?ws={ws_port}")
                res = run_gui_journey(
                    model, driver, journey, izba_bin=args.izba_bin, data_dir=jdir,
                    max_turns=args.max_turns, step_cap=args.step_cap,
                    action_timeout_s=args.action_timeout_s,
                    latency_budget_ms=args.latency_budget_ms,
                    budget=budget, max_usd=args.max_usd, artifact_dir=args.artifact_dir)
                driver.close()
                results.append(res)
            except BudgetExceeded:
                log("budget exhausted; stopping"); break
            except Exception as e:  # report-only
                log(f"journey {jid!r} crashed: {e!r}")
                results.append({"journey_id": jid, "actions": [], "candidates": []})
            finally:
                sidecar.terminate()
                try:
                    sidecar.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    sidecar.kill()
    finally:
        httpd.shutdown()

    bundle = {"shard": args.shard, "feature": feature, "results": results}
    with open(args.out, "w") as f:
        json.dump(bundle, f, indent=2)
    log(f"wrote {args.out}: {len(results)} journeys, est. ${budget['usd']:.4f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

> Confirmed: `izba __reconcile --json` is exactly what the CLI loop shells (`oracles._snapshot_reconcile`, `oracles.py:152-157`). `_reconcile_snapshot` here mirrors it; you may instead import and reuse `oracles._snapshot_reconcile` if you prefer (it takes `(izba_bin, data_dir, timeout_s, run_env)` and returns the snapshot dict).

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest hack/dogfood/gui/test_run_gui_journeys.py -q`
Expected: PASS (3 passed).

- [ ] **Step 5: Run the whole dogfood suite (no regressions)**

Run: `python3 -m pytest hack/dogfood -q`
Expected: PASS (all existing + new).

- [ ] **Step 6: Commit**

```bash
git add hack/dogfood/gui/run_gui_journeys.py hack/dogfood/gui/test_run_gui_journeys.py
git commit -m "feat(dogfood): add GUI Actor loop (run_gui_journeys) reusing daemon-truth oracles"
```

---

## Phase 2 — Rust bridge sidecar + in-page bridge + dogfood frontend build

### Task 7: `app_lib::dispatch` + `bin/headless` WS sidecar

**Files:**
- Modify: `app/src-tauri/Cargo.toml` (add `tungstenite` dep + `[[bin]]`)
- Modify: `app/src-tauri/src/lib.rs` (add `pub fn dispatch` + make `mod commands`/`views` reachable from it — they already are; only `dispatch` is new and `pub`)
- Create: `app/src-tauri/src/bin/headless.rs`
- Test: `app/src-tauri/src/lib.rs` (a `#[cfg(test)]` module using `fake::FakeDaemon`)

**Interfaces:**
- Produces: `pub fn dispatch(state: &AppState, cmd: &str, args: serde_json::Value, emit: &mut dyn FnMut(&str, serde_json::Value)) -> Result<serde_json::Value, String>`. Handles the non-shell commands the skeleton needs (`list`, `daemon_status`, `version_info`, `create`, `start`, `stop`, `restart`, `remove`, `policy_show`, `policy_set_enforce`, `inspect`, `read_logs`); `shell_*` return `Err("shell not supported in dogfood headless (deferred)")`; unknown cmd → `Err`.
- WS message contract (consumed by `real-bridge.js`, Task 8): client→sidecar `{"id": <n>, "cmd": <str>, "args": <obj>}`; sidecar→client reply `{"id": <n>, "ok": true, "result": <json>}` or `{"id": <n>, "ok": false, "error": <str>}`; sidecar→client event `{"type": "event", "event": <str>, "payload": <json>}`.

- [ ] **Step 1: Write the failing test (in `lib.rs`)**

Add at the end of `app/src-tauri/src/lib.rs`:

```rust
#[cfg(test)]
mod dispatch_tests {
    use super::*;
    use crate::fake::FakeDaemon;
    use std::sync::{Arc, Mutex};

    fn state_with(d: FakeDaemon) -> AppState {
        AppState {
            daemon: Mutex::new(Box::new(d)),
            make_daemon: Arc::new(|| Box::new(FakeDaemon::default())),
            shells: Mutex::new(std::collections::HashMap::new()),
        }
    }

    #[test]
    fn dispatch_list_returns_sandbox_json() {
        let st = state_with(FakeDaemon::default());
        let mut emit = |_: &str, _: serde_json::Value| {};
        let out = dispatch(&st, "list", serde_json::json!({}), &mut emit).unwrap();
        assert!(out.is_array());
    }

    #[test]
    fn dispatch_unknown_cmd_errors() {
        let st = state_with(FakeDaemon::default());
        let mut emit = |_: &str, _: serde_json::Value| {};
        assert!(dispatch(&st, "no_such_cmd", serde_json::json!({}), &mut emit).is_err());
    }

    #[test]
    fn dispatch_shell_open_is_deferred_error() {
        let st = state_with(FakeDaemon::default());
        let mut emit = |_: &str, _: serde_json::Value| {};
        let e = dispatch(&st, "shell_open",
                         serde_json::json!({"name": "a", "id": "s1"}), &mut emit);
        assert!(e.is_err());
    }
}
```

> Confirmed: `fake.rs` already has `impl Default for FakeDaemon` (`fake.rs:63`), so `FakeDaemon::default()` works here. (If a journey needs the fake to report a sandbox, set its fields after `default()` per `fake.rs`.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cd app/src-tauri && cargo test dispatch_tests`
Expected: FAIL — `cannot find function dispatch`.

- [ ] **Step 3a: Add `dispatch` to `lib.rs`**

Add (near the top-level fns, before `run()`), reusing the existing `commands::*_core` and `CreateOpts`:

```rust
/// Headless invoke dispatcher: the same command→core-fn mapping the
/// `#[tauri::command]` shims use, but transport-agnostic. Used by the dogfood
/// bridge sidecar (`bin/headless`) to drive the real command/view/daemon layer
/// from a browser without the Tauri runtime. `emit` carries Tauri events
/// (e.g. `create-progress`) back to the caller.
///
/// Shell commands are intentionally unsupported here (deferred — see the GUI
/// dogfooding spec §10); they return an explicit error rather than a stub.
pub fn dispatch(
    state: &AppState,
    cmd: &str,
    args: serde_json::Value,
    emit: &mut dyn FnMut(&str, serde_json::Value),
) -> Result<serde_json::Value, String> {
    use serde_json::json;

    fn arg_str(args: &serde_json::Value, key: &str) -> Result<String, String> {
        args.get(key)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| format!("missing string arg '{key}'"))
    }
    fn to_json<T: serde::Serialize>(v: T) -> Result<serde_json::Value, String> {
        serde_json::to_value(v).map_err(|e| format!("serialize error: {e}"))
    }

    let mut d = state
        .daemon
        .lock()
        .map_err(|e| format!("state poisoned: {e}"))?;
    let d = d.as_mut();
    match cmd {
        "list" => to_json(commands::list_core(d)?),
        "daemon_status" => to_json(commands::status_core(d)?),
        "version_info" => to_json(commands::version_core(d)?),
        "read_logs" => to_json(commands::read_logs_core(d, &arg_str(&args, "name")?)?),
        "start" => to_json(commands::start_core(d, &arg_str(&args, "name")?)?),
        "stop" => to_json(commands::stop_core(d, &arg_str(&args, "name")?)?),
        "restart" => to_json(commands::restart_core(d, &arg_str(&args, "name")?)?),
        "remove" => {
            let force = args.get("force").and_then(|v| v.as_bool()).unwrap_or(false);
            to_json(commands::remove_core(d, &arg_str(&args, "name")?, force)?)
        }
        "inspect" => to_json(commands::inspect_core(d, &arg_str(&args, "name")?)?),
        "policy_show" => to_json(commands::policy_show_core(d, &arg_str(&args, "name")?)?),
        "policy_set_enforce" => {
            let on = args.get("on").and_then(|v| v.as_bool()).unwrap_or(false);
            to_json(commands::policy_set_enforce_core(d, &arg_str(&args, "name")?, on)?)
        }
        "create" => {
            let opts: views::CreateOpts = serde_json::from_value(
                args.get("opts").cloned().unwrap_or(serde_json::Value::Null))
                .map_err(|e| format!("bad create opts: {e}"))?;
            let name = commands::create_core(d, opts, &mut |m| {
                emit("create-progress", json!(m));
            })?;
            to_json(name)
        }
        "shell_open" | "shell_write" | "shell_resize" | "shell_close" => {
            Err("shell not supported in dogfood headless (deferred)".to_string())
        }
        other => Err(format!("unknown command: {other}")),
    }
}
```

> The skeleton journeys (Task 11) use only the commands above. Adding the remaining commands (policy_allow/port_*/volume_*) later is mechanical — one match arm each, same `arg_str`/`to_json` pattern.

- [ ] **Step 3b: Make `fake.rs` available to non-test builds? No — keep it test-only.** The `dispatch_tests` module is `#[cfg(test)]`, so `crate::fake::FakeDaemon` is fine. Ensure `mod fake;` stays `#[cfg(test)]`.

- [ ] **Step 4: Run the dispatch tests to verify they pass**

Run: `cd app/src-tauri && cargo test dispatch_tests`
Expected: PASS (3 tests).

- [ ] **Step 5: Add the WS sidecar bin + dep**

In `app/src-tauri/Cargo.toml`, add under `[dependencies]`:

```toml
# Dogfood bridge sidecar transport (sync WebSocket; test/dogfood only).
tungstenite = "0.24"
serde_json = "1"
```

(`serde_json` is already present — keep one entry.) And add a bin target:

```toml
[[bin]]
name = "headless"
path = "src/bin/headless.rs"
```

Create `app/src-tauri/src/bin/headless.rs`:

```rust
//! Dogfood bridge sidecar: a single-client sync WebSocket server that drives
//! the real izba-app command/view/daemon layer (`app_lib::dispatch`) from a
//! browser. NOT shipped in the app; built only for GUI dogfooding.
//!
//! Protocol (text frames, JSON):
//!   client→  {"id":N,"cmd":"create","args":{...}}
//!   →client  {"type":"event","event":"create-progress","payload":"..."}   (0+)
//!   →client  {"id":N,"ok":true,"result":<json>}  |  {"id":N,"ok":false,"error":"..."}
//!
//! Port from $IZBA_DOGFOOD_WS_PORT (default 17890). IZBA_DATA_DIR selects the
//! daemon's data dir (RealDaemon::new reads it). Events are buffered during a
//! command and flushed before that command's reply — adequate for create
//! progress; live shell streaming is deferred (shell cmds return an error).
use std::collections::HashMap;
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use app_lib::{dispatch, AppState};

#[cfg_attr(test, mutants::skip)] // reason: process/socket glue, e2e-only
fn main() {
    let port: u16 = std::env::var("IZBA_DOGFOOD_WS_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(17890);
    let listener = TcpListener::bind(("127.0.0.1", port))
        .unwrap_or_else(|e| panic!("bind 127.0.0.1:{port}: {e}"));
    let state = AppState {
        daemon: Mutex::new(Box::new(app_lib::new_real_daemon())),
        make_daemon: Arc::new(|| Box::new(app_lib::new_real_daemon())),
        shells: Mutex::new(HashMap::new()),
    };
    // Single client (one browser). Re-accept on disconnect so a page reload
    // re-attaches.
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let mut ws = match tungstenite::accept(stream) {
            Ok(w) => w,
            Err(_) => continue,
        };
        loop {
            let msg = match ws.read() {
                Ok(m) => m,
                Err(_) => break,
            };
            if !msg.is_text() {
                continue;
            }
            let req: serde_json::Value = match serde_json::from_str(msg.to_text().unwrap_or("")) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let id = req.get("id").cloned().unwrap_or(serde_json::Value::Null);
            let cmd = req.get("cmd").and_then(|v| v.as_str()).unwrap_or("");
            let args = req.get("args").cloned().unwrap_or(serde_json::json!({}));

            let mut events: Vec<(String, serde_json::Value)> = Vec::new();
            let result = dispatch(&state, cmd, args, &mut |ev, payload| {
                events.push((ev.to_string(), payload));
            });
            // Flush events first, then the reply.
            for (ev, payload) in events {
                let frame = serde_json::json!({"type": "event", "event": ev, "payload": payload});
                let _ = ws.send(tungstenite::Message::Text(frame.to_string().into()));
            }
            let reply = match result {
                Ok(v) => serde_json::json!({"id": id, "ok": true, "result": v}),
                Err(e) => serde_json::json!({"id": id, "ok": false, "error": e}),
            };
            if ws.send(tungstenite::Message::Text(reply.to_string().into())).is_err() {
                break;
            }
        }
    }
}
```

In `app/src-tauri/src/lib.rs`, expose the `RealDaemon` constructor for the bin (the bin is a separate crate and cannot name `daemon::RealDaemon` directly):

```rust
/// Constructor the dogfood bridge bin uses to build a real daemon connection.
pub fn new_real_daemon() -> Box<dyn DaemonApi> {
    Box::new(RealDaemon::new())
}
```

> Verify the `tungstenite` 0.24 API at compile time: `accept`, `WebSocket::read`/`send`, and `Message::Text` (the `.into()` on the payload is for the `Utf8Bytes`/`String` arg — adjust to `Message::Text(frame.to_string())` if the version takes a plain `String`). This is the one spot to reconcile against the resolved crate version.

- [ ] **Step 6: Build the bin + run all app backend tests**

Run: `cd app/src-tauri && cargo build --bin headless && cargo test`
Expected: builds; all tests pass.

- [ ] **Step 7: Commit**

```bash
git add app/src-tauri/Cargo.toml app/src-tauri/src/lib.rs app/src-tauri/src/bin/headless.rs
git commit -m "feat(app): add headless dogfood bridge sidecar (dispatch + WS server)"
```

### Task 8: `real-bridge.js` — WS-backed in-page Tauri bridge

**Files:**
- Create: `app/dogfood/real-bridge.js`
- Test: `app/src/test/realBridge.test.ts` (a jsdom unit test of the message protocol)

**Interfaces:**
- Consumes: the WS contract from Task 7.
- Produces: an in-page script that defines `window.__TAURI_INTERNALS__.invoke`, `transformCallback`, the event registry + `__TAURI_EVENT_PLUGIN_INTERNALS__.unregisterListener`, and populates `window.__DF_CONSOLE_ERRORS__` (via `onerror`/`onunhandledrejection`) and `window.__DF_INVOKE_LOG__` (`{cmd, ok, error}` per resolved invoke). Reads the WS port from `?ws=` in `location.search`.
- For testability the file exports a pure `__dfHandleMessage(state, raw)` used by the test; in the browser it self-installs.

- [ ] **Step 1: Write the failing test**

```ts
// app/src/test/realBridge.test.ts
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

// Load the bridge source and eval its exported pure helper in jsdom.
const SRC = readFileSync(resolve(__dirname, "../../dogfood/real-bridge.js"), "utf8");

function loadHelper() {
  const mod: any = {};
  // The file ends with: if (typeof module!=='undefined') module.exports={__dfHandleMessage};
  // eslint-disable-next-line no-new-func
  new Function("module", "window", SRC)(mod, { addEventListener() {}, location: { search: "" } });
  return mod.exports.__dfHandleMessage;
}

describe("real-bridge protocol", () => {
  it("resolves a pending invoke on an ok reply and logs it", () => {
    const handle = loadHelper();
    let resolved: any = null;
    const state = {
      pending: new Map([[1, { resolve: (v: any) => (resolved = v), reject: () => {} }]]),
      listeners: new Map(),
      invokeLog: [] as any[],
      lastCmd: new Map([[1, "list"]]),
    };
    handle(state, JSON.stringify({ id: 1, ok: true, result: [{ name: "web" }] }));
    expect(resolved).toEqual([{ name: "web" }]);
    expect(state.invokeLog).toEqual([{ cmd: "list", ok: true, error: "" }]);
    expect(state.pending.size).toBe(0);
  });

  it("fires event listeners on an event frame", () => {
    const handle = loadHelper();
    let got: any = null;
    const state = {
      pending: new Map(),
      listeners: new Map([["create-progress", new Set([(p: any) => (got = p)])]]),
      invokeLog: [],
      lastCmd: new Map(),
    };
    handle(state, JSON.stringify({ type: "event", event: "create-progress", payload: "pulling" }));
    expect(got).toEqual({ event: "create-progress", payload: "pulling" });
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd app && npx vitest run src/test/realBridge.test.ts`
Expected: FAIL — file not found.

- [ ] **Step 3: Implement `app/dogfood/real-bridge.js`**

```js
// app/dogfood/real-bridge.js
// In-page Tauri bridge for GUI dogfooding. Same surface as e2e/mock/tauri-mock.js,
// but instead of canned scenario data it forwards invoke() over a WebSocket to
// the headless dogfood sidecar (app_lib::dispatch) and fires Tauri events from
// the sidecar back to the app. Also records uncaught errors and an invoke log
// for the dogfood oracles. Loaded as the FIRST <script> in the dogfood
// index.html so it defines __TAURI_INTERNALS__ before the app bundle runs.
(function () {
  // ---- pure protocol handler (also exported for unit tests) ----
  function __dfHandleMessage(state, raw) {
    var msg;
    try {
      msg = JSON.parse(raw);
    } catch (e) {
      return;
    }
    if (msg && msg.type === "event") {
      var set = state.listeners.get(msg.event);
      if (set) {
        set.forEach(function (fn) {
          if (typeof fn === "function") fn({ event: msg.event, payload: msg.payload });
        });
      }
      return;
    }
    if (msg && typeof msg.id !== "undefined" && state.pending.has(msg.id)) {
      var p = state.pending.get(msg.id);
      state.pending.delete(msg.id);
      var cmd = state.lastCmd.get(msg.id) || "";
      state.lastCmd.delete(msg.id);
      if (msg.ok) {
        state.invokeLog.push({ cmd: cmd, ok: true, error: "" });
        p.resolve(msg.result);
      } else {
        state.invokeLog.push({ cmd: cmd, ok: false, error: String(msg.error || "") });
        p.reject(new Error(String(msg.error || "invoke failed")));
      }
    }
  }

  if (typeof module !== "undefined" && module) {
    module.exports = { __dfHandleMessage: __dfHandleMessage };
    if (typeof window === "undefined") return; // unit-test load: stop here
  }

  // ---- browser install ----
  var win = window;
  win.__DF_CONSOLE_ERRORS__ = win.__DF_CONSOLE_ERRORS__ || [];
  win.__DF_INVOKE_LOG__ = win.__DF_INVOKE_LOG__ || [];
  win.addEventListener("error", function (e) {
    win.__DF_CONSOLE_ERRORS__.push(String((e && e.message) || e));
  });
  win.addEventListener("unhandledrejection", function (e) {
    win.__DF_CONSOLE_ERRORS__.push("unhandledrejection: " + String((e && e.reason) || e));
  });

  var state = {
    pending: new Map(),
    listeners: new Map(),
    invokeLog: win.__DF_INVOKE_LOG__,
    lastCmd: new Map(),
  };
  var nextId = 1;
  var queue = [];
  var ws = null;

  function wsPort() {
    var m = /[?&]ws=(\d+)/.exec(win.location.search || "");
    return m ? m[1] : "17890";
  }
  function connect() {
    ws = new WebSocket("ws://127.0.0.1:" + wsPort());
    ws.onmessage = function (ev) {
      __dfHandleMessage(state, ev.data);
    };
    ws.onopen = function () {
      queue.splice(0).forEach(function (f) {
        ws.send(f);
      });
    };
    ws.onclose = function () {
      setTimeout(connect, 300);
    };
  }
  connect();

  var internals = (win.__TAURI_INTERNALS__ = win.__TAURI_INTERNALS__ || {});
  internals.transformCallback = function (callback, once) {
    var id = win.crypto.getRandomValues(new Uint32Array(1))[0];
    var prop = "_" + id;
    Object.defineProperty(win, prop, {
      value: function (result) {
        if (once) Reflect.deleteProperty(win, prop);
        return callback && callback(result);
      },
      writable: false,
      configurable: true,
    });
    return id;
  };
  var eventInternals = (win.__TAURI_EVENT_PLUGIN_INTERNALS__ =
    win.__TAURI_EVENT_PLUGIN_INTERNALS__ || {});
  eventInternals.unregisterListener = function (event, id) {
    var set = state.listeners.get(event);
    if (set) set.delete(id);
  };

  internals.invoke = function (cmd, args) {
    args = args || {};
    // Tauri's event plugin commands are handled in-page, not by the sidecar.
    if (cmd === "plugin:event|listen") {
      var set = state.listeners.get(args.event) || new Set();
      var handler = function (e) {
        var fn = win["_" + args.handler];
        if (typeof fn === "function") fn(e);
      };
      handler.__id = args.handler;
      set.add(handler);
      state.listeners.set(args.event, set);
      return Promise.resolve(args.handler);
    }
    if (cmd === "plugin:event|unlisten") {
      var s = state.listeners.get(args.event);
      if (s) s.forEach(function (h) { if (h.__id === args.eventId) s.delete(h); });
      return Promise.resolve();
    }
    if (cmd === "plugin:event|emit" || cmd === "plugin:event|emit_to") {
      return Promise.resolve();
    }
    // Real backend call.
    var id = nextId++;
    state.lastCmd.set(id, cmd);
    var frame = JSON.stringify({ id: id, cmd: cmd, args: args });
    var promise = new Promise(function (resolve, reject) {
      state.pending.set(id, { resolve: resolve, reject: reject });
    });
    if (ws && ws.readyState === 1) ws.send(frame);
    else queue.push(frame);
    return promise;
  };
})();
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd app && npx vitest run src/test/realBridge.test.ts`
Expected: PASS (2 tests).

> Note: `npx` is banned in CI workflow YAML (SonarCloud S8543) but is fine for a local dev run. The CI run uses `npm run test:unit`-style scripts (Task 12) which already wrap vitest.

- [ ] **Step 5: Commit**

```bash
git add app/dogfood/real-bridge.js app/src/test/realBridge.test.ts
git commit -m "feat(app): add WS-backed real-bridge.js for GUI dogfooding"
```

### Task 9: dogfood frontend build (inject the bridge first)

**Files:**
- Create: `app/dogfood/inject.mjs` (post-build: copy `real-bridge.js` into dist + inject as first script)
- Modify: `app/package.json` (add a `build:dogfood` script)
- Test: `app/src/test/dogfoodBuild.test.ts` (asserts the injection logic on a fixture HTML string)

**Interfaces:**
- Produces: `npm run build:dogfood` → `app/dist` whose `index.html` loads `/real-bridge.js` before the app module bundle, and `app/dist/real-bridge.js` present.
- Pure helper `injectBridge(html: string): string` exported from `inject.mjs` for the test.

- [ ] **Step 1: Write the failing test**

```ts
// app/src/test/dogfoodBuild.test.ts
import { describe, it, expect } from "vitest";
import { injectBridge } from "../../dogfood/inject.mjs";

describe("dogfood bridge injection", () => {
  it("inserts real-bridge.js as the first script, before the module bundle", () => {
    const html =
      '<!doctype html><html><head><title>x</title></head>' +
      '<body><script type="module" src="/assets/index-abc.js"></script></body></html>';
    const out = injectBridge(html);
    const bridgeIdx = out.indexOf("/real-bridge.js");
    const bundleIdx = out.indexOf("/assets/index-abc.js");
    expect(bridgeIdx).toBeGreaterThan(-1);
    expect(bridgeIdx).toBeLessThan(bundleIdx);
  });

  it("is idempotent (no double injection)", () => {
    const html = '<head></head><body><script type="module" src="/x.js"></script></body>';
    expect(injectBridge(injectBridge(html))).toBe(injectBridge(html));
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd app && npx vitest run src/test/dogfoodBuild.test.ts`
Expected: FAIL — cannot resolve `inject.mjs`.

- [ ] **Step 3: Implement `app/dogfood/inject.mjs`**

```js
// app/dogfood/inject.mjs
// Post-build step: make app/dist a *dogfood* build by loading the WS bridge
// before the app bundle, so __TAURI_INTERNALS__ is the real-bridge one.
import { readFileSync, writeFileSync, copyFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const BRIDGE_TAG = '<script src="/real-bridge.js"></script>';

export function injectBridge(html) {
  if (html.includes(BRIDGE_TAG)) return html; // idempotent
  // Insert right after <head> (so it runs before any module script in <body>).
  if (html.includes("<head>")) return html.replace("<head>", "<head>" + BRIDGE_TAG);
  return BRIDGE_TAG + html;
}

// CLI: `node dogfood/inject.mjs <dist-dir>`
if (import.meta.url === `file://${process.argv[1]}`) {
  const dist = resolve(process.argv[2] || "dist");
  const indexPath = resolve(dist, "index.html");
  writeFileSync(indexPath, injectBridge(readFileSync(indexPath, "utf8")));
  copyFileSync(resolve(HERE, "real-bridge.js"), resolve(dist, "real-bridge.js"));
  console.log(`[dogfood] injected real-bridge.js into ${indexPath}`);
}
```

- [ ] **Step 4: Add the build script**

In `app/package.json` `scripts`, add:

```json
    "build:dogfood": "vite build && node dogfood/inject.mjs dist",
```

- [ ] **Step 5: Run the test + a real build to verify**

Run: `cd app && npx vitest run src/test/dogfoodBuild.test.ts && npm run build:dogfood && test -f dist/real-bridge.js && grep -q real-bridge.js dist/index.html && echo OK`
Expected: tests PASS; `OK` printed.

- [ ] **Step 6: Commit**

```bash
git add app/dogfood/inject.mjs app/package.json app/src/test/dogfoodBuild.test.ts
git commit -m "feat(app): add build:dogfood (inject WS bridge before app bundle)"
```

---

## Phase 3 — CI integration, journeys, agents, docs

### Task 10: Local smoke script (manual end-to-end check before CI)

**Files:**
- Create: `hack/dogfood/gui/smoke.sh`

**Interfaces:**
- Produces: a documented manual command that builds the dogfood dist + sidecar, serves it, and runs one fake-model journey against a real daemon — so a developer can validate the bridge before paying for a CI swarm.

- [ ] **Step 1: Write `hack/dogfood/gui/smoke.sh`**

```bash
#!/usr/bin/env bash
# Manual GUI-dogfood smoke: build the dogfood dist + sidecar, then run ONE
# fake-model journey against a real izbad. Requires a working izba install
# (real microVMs) + agent-browser on PATH. NOT a CI gate — a dev sanity check.
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT/app" && npm ci && npm run build:dogfood
cd "$ROOT/app/src-tauri" && cargo build --release --bin headless
DIST="$ROOT/app/dist"
SIDE="$ROOT/app/src-tauri/target/release/headless"
DATA="$(mktemp -d /tmp/izd-smoke.XXXX)"
python3 "$ROOT/hack/dogfood/gui/run_gui_journeys.py" \
  --journeys "$ROOT/hack/dogfood/fixtures/journeys.gui-skeleton.json" \
  --izba-bin "$(command -v izba)" \
  --sidecar-bin "$SIDE" \
  --frontend-dir "$DIST" \
  --data-dir "$DATA" \
  --out /tmp/gui-traj.json \
  --fake-model '[{"read":true},{"done":true}]'
echo "wrote /tmp/gui-traj.json"
```

- [ ] **Step 2: Make it executable + commit**

```bash
chmod +x hack/dogfood/gui/smoke.sh
git add hack/dogfood/gui/smoke.sh
git commit -m "chore(dogfood): add manual GUI-dogfood smoke script"
```

### Task 11: The 5 skeleton GUI journeys

**Files:**
- Create: `hack/dogfood/fixtures/journeys.gui-skeleton.json`
- Test: append to `hack/dogfood/test_schema_gui.py`

**Interfaces:**
- Produces: a `journeys.json`-shaped file with `feature` + 5 `modality:"gui"` journeys (create→start→shell→policy→remove), each `source.kind` = `spec`, intents in UI-user language, expects DOM-observable. Default tier `core`.

- [ ] **Step 1: Write the failing test (append)**

```python
def test_gui_skeleton_journeys_are_gui_and_anchored():
    with open(os.path.join(HERE, "fixtures", "journeys.gui-skeleton.json")) as f:
        doc = json.load(f)
    assert len(doc["journeys"]) == 5
    for j in doc["journeys"]:
        assert j["modality"] == "gui"
        assert j["source"]["ref"]
        assert j["steps"] and all(s["intent"] and s["expect"] for s in j["steps"])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest hack/dogfood/test_schema_gui.py -q`
Expected: FAIL — fixture missing.

- [ ] **Step 3: Create `hack/dogfood/fixtures/journeys.gui-skeleton.json`**

```json
{
  "feature": "izba desktop app (GUI dogfood walking skeleton)",
  "journeys": [
    {
      "journey_id": "gui-create-sandbox",
      "modality": "gui",
      "rationale": "A user can create a sandbox from the app and see it appear.",
      "source": { "kind": "spec", "ref": "2026-06-30-gui-dogfooding-design.md §9.1" },
      "steps": [
        { "intent": "create a new sandbox named web using the default image",
          "expect": "a sandbox named web appears in the sandbox list" }
      ]
    },
    {
      "journey_id": "gui-start-sandbox",
      "modality": "gui",
      "rationale": "A user can start a created sandbox and the app shows it running.",
      "source": { "kind": "spec", "ref": "2026-06-30-gui-dogfooding-design.md §9.2" },
      "steps": [
        { "intent": "create a sandbox named web", "expect": "web appears in the list" },
        { "intent": "start the sandbox named web", "expect": "web is shown as running" }
      ]
    },
    {
      "journey_id": "gui-open-shell",
      "modality": "gui",
      "rationale": "A user can open a shell into a running sandbox.",
      "source": { "kind": "spec", "ref": "2026-06-30-gui-dogfooding-design.md §9.3" },
      "steps": [
        { "intent": "create and start a sandbox named web", "expect": "web is running" },
        { "intent": "open a shell or terminal for web", "expect": "a terminal/shell view for web is shown" }
      ]
    },
    {
      "journey_id": "gui-enforce-policy",
      "modality": "gui",
      "rationale": "A user can turn on firewall enforcement for a sandbox.",
      "source": { "kind": "spec", "ref": "2026-06-30-gui-dogfooding-design.md §9.4" },
      "steps": [
        { "intent": "create a sandbox named web", "expect": "web appears in the list" },
        { "intent": "open web's firewall/policy settings and turn enforcement on",
          "expect": "the firewall for web shows as enforcing" }
      ]
    },
    {
      "journey_id": "gui-remove-sandbox",
      "modality": "gui",
      "rationale": "A user can remove a sandbox and it disappears from the app.",
      "source": { "kind": "spec", "ref": "2026-06-30-gui-dogfooding-design.md §9.5" },
      "steps": [
        { "intent": "create a sandbox named web", "expect": "web appears in the list" },
        { "intent": "remove the sandbox named web, confirming if asked",
          "expect": "web no longer appears in the sandbox list" }
      ]
    }
  ]
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `python3 -m pytest hack/dogfood/test_schema_gui.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add hack/dogfood/fixtures/journeys.gui-skeleton.json hack/dogfood/test_schema_gui.py
git commit -m "feat(dogfood): add 5 GUI walking-skeleton journeys"
```

### Task 12: `dogfood.yml` — the `dogfood-gui` job

**Files:**
- Modify: `.github/workflows/dogfood.yml` (add a `dogfood-gui` job; add a `gui` boolean dispatch input)

**Interfaces:**
- Consumes: the `kernel` + `initramfs` artifacts and runtime-tools cache already produced for the `dogfood` job; the `OPENROUTER_API_KEY` secret.
- Produces: per-shard `gui-traj-<shard>.json` artifacts + on-failure screenshots/logs.

- [ ] **Step 1: Add the job (after the existing `dogfood` job)**

```yaml
  dogfood-gui:
    name: dogfood GUI journeys (KVM shard ${{ matrix.shard }})
    needs: [kernel, initramfs]
    runs-on: ubuntu-latest
    timeout-minutes: 70
    strategy:
      fail-fast: false
      matrix:
        shard: [0, 1, 2]
    env:
      IZBA_KERNEL: ${{ github.workspace }}/dist/vmlinux
      IZBA_INITRAMFS: ${{ github.workspace }}/dist/initramfs.cpio.gz
      IZBA_TEST_CACHE: /home/runner/.cache/izba-itest
      IZBA_BOOT_TIMEOUT_SECS: '120'
    steps:
      - name: Guard — matrix is fixed at 3 shards
        env:
          SHARDS: ${{ inputs.shards }}
        run: |
          if [ "$SHARDS" != "3" ]; then
            echo "::error::dogfood.yml matrix is fixed at 3 shards but shards=$SHARDS"; exit 1
          fi
      - uses: actions/checkout@9f698171ed81b15d1823a05fc7211befd50c8ae0 # v6.0.3
      - name: Make /dev/kvm accessible
        run: |
          echo 'KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"' \
            | sudo tee /etc/udev/rules.d/99-kvm4all.rules
          sudo udevadm control --reload-rules
          sudo udevadm trigger --name-match=kvm || true
          [ -r /dev/kvm ] && [ -w /dev/kvm ]
      - name: Allow unprivileged user namespaces (virtiofsd --sandbox namespace)
        run: |
          if [ -e /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]; then
            sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
          fi
      - name: Restore runtime tools
        id: tools
        uses: actions/cache@27d5ce7f107fe9357f9df03efb73ab90386fccae # v5.0.5
        with:
          path: |
            ~/.local/bin/cloud-hypervisor
            ~/.local/bin/virtiofsd
            ~/.local/bin/mkfs.erofs
          key: e2e-tools-${{ hashFiles('hack/fetch-artifacts.sh', 'hack/build-mkfs-erofs-windows.sh') }}
      - name: Build runtime tools (cache miss)
        if: steps.tools.outputs.cache-hit != 'true'
        run: |
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends \
            curl tar make gcc autoconf automake libtool-bin pkg-config patch unzip file
          mkdir -p "$HOME/.local/bin"
          IZBA_BIN_DIR="$HOME/.local/bin" hack/fetch-artifacts.sh || true
          hack/build-mkfs-erofs-windows.sh --linux-only
          install -m755 "$HOME/.cache/izba/erofs-utils/build-linux/mkfs/mkfs.erofs" "$HOME/.local/bin/mkfs.erofs"
      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        with: { name: vmlinux, path: dist/ }
      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        with: { name: initramfs, path: dist/ }
      - name: Restore OCI test-image cache
        uses: actions/cache@27d5ce7f107fe9357f9df03efb73ab90386fccae # v5.0.5
        with: { path: /home/runner/.cache/izba-itest, key: izba-itest-alpine-3.20 }
      - uses: Swatinem/rust-cache@23869a5bd66c73db3c0ac40331f3206eb23791dc # v2.9.1
        with: { prefix-key: dogfood-gui-linux }
      - name: Build izba binary + headless bridge sidecar
        run: |
          cargo build --locked --release -p izba-cli
          (cd app/src-tauri && cargo build --release --bin headless)
      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0
        with: { node-version: '20' }
      - name: Build dogfood frontend
        run: cd app && npm ci && npm run build:dogfood
      - name: Install agent-browser (pinned) + browser
        run: |
          npm i -g agent-browser@0.31.1
          agent-browser install --with-deps
      - name: Run GUI dogfood journeys (report-only)
        env:
          OPENROUTER_API_KEY: ${{ secrets.OPENROUTER_API_KEY }}
          SHARD: ${{ matrix.shard }}
          SHARDS: ${{ inputs.shards }}
          MODEL: ${{ inputs.model }}
          MAX_USD: ${{ inputs.max_usd }}
        run: |
          export PATH="$HOME/.local/bin:$PATH"
          python3 hack/dogfood/gui/run_gui_journeys.py \
            --journeys journeys.json \
            --shard "$SHARD" --shards "$SHARDS" \
            --izba-bin "$PWD/target/release/izba" \
            --sidecar-bin "$PWD/app/src-tauri/target/release/headless" \
            --frontend-dir "$PWD/app/dist" \
            --data-dir "/tmp/izd-gui-$SHARD" \
            --out "gui-traj-$SHARD.json" \
            --artifact-dir "gui-shots-$SHARD" \
            --model "$MODEL" --max-usd "$MAX_USD" \
            --readme README.md --app-guide dogfood-app-guide.md \
            --action-timeout-s 30 --step-cap 20
      - name: Upload GUI trajectory bundle
        if: always()
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: gui-traj-${{ matrix.shard }}
          path: |
            gui-traj-${{ matrix.shard }}.json
            gui-shots-${{ matrix.shard }}/**
          if-no-files-found: warn
```

> The GUI journeys travel in the same root `journeys.json` on the `dogfood-run/<feature>` branch as CLI journeys; `run_gui_journeys.py` selects `modality:"gui"` and the CLI runner selects the rest. The `dogfood-app-guide.md` (a user-facing app overview, no source/spec) is committed at the repo root on the dispatch branch, mirroring `dogfood-context.md`.

- [ ] **Step 2: Validate the workflow YAML**

Run: `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/dogfood.yml'))" && echo OK`
Expected: `OK` (valid YAML).

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/dogfood.yml
git commit -m "ci(dogfood): add dogfood-gui job (agent-browser + headless bridge over KVM)"
```

### Task 13: Teach the Phase-1/Phase-3 subagents the GUI modality

**Files:**
- Modify: `.claude/agents/journey-compiler.md` (add a GUI-modality subsection under "What you produce")
- Modify: `.claude/agents/trajectory-skeptic.md` (add a GUI-trajectory subsection)

**Interfaces:** documentation-only; no code.

- [ ] **Step 1: Append to `journey-compiler.md`** (a new `## Mandate 7 — GUI journeys (modality)` section before "Validation"):

```markdown
## Mandate 7 — GUI journeys (modality)

When the feature has a desktop-app (Tauri) surface, also emit `modality: "gui"`
journeys (CLI journeys stay `modality:"cli"` / absent). For GUI journeys:

- `intent` is a UI goal in **user** language ("create a sandbox named web and
  open a shell in it") — never a component name, selector, or invoke command.
- `expect` is **DOM-observable**: text or a control a user would see ("web is
  shown as running"), never an exit code or internal state.
- Launder the same way: nothing about `src/components`, `data-testid`s, the IPC
  command names, or the spec leaks into intent/expect or the context pack.
- The fair-test context pack for GUI runs is the app's user-facing guide
  (`dogfood-app-guide.md`) + README — the docs a user reads, not the source.
- A control the journey needs that has no accessible name is a *predicted
  discoverability finding* (Mandate 5), not a reason to name an internal handle.
```

- [ ] **Step 2: Append to `trajectory-skeptic.md`** (a new `## GUI trajectories` section before "Rules"):

```markdown
## GUI trajectories

GUI journeys (`modality:"gui"`) carry, per action, the accessibility `snapshot`
the Actor saw, `console_errors`, and on failure a `screenshot_ref` (annotated
with the same `@e` refs). Candidate kinds extend to `console`, `ui_daemon_diff`,
`silent_failure`, `dom_expect`. Apply the same bidirectional skepticism:

- **Refute reds:** a `dom_expect` miss may be Actor fumbling (gave up early,
  never reached the screen) rather than a product gap — check the snapshots.
  A `console` error in third-party noise is not a product bug; one from the app's
  own code is. `silent_failure` is real only if the invoke truly rejected AND no
  error surface appears in the *final* snapshot.
- **Audit greens:** a journey that "succeeded" must have reached its `expect`
  through the UI. The **`ui_daemon_diff` = empty** check is your strongest ally:
  the daemon state-evidence is ground truth; if the UI claimed success but
  `state_evidence.sandboxes` disagrees, the green is a lie.
- A control the Actor could not find (it stalled, no matching ref) is a
  discoverability/a11y finding, not Actor weakness — confirm via the snapshots.
```

- [ ] **Step 3: Commit**

```bash
git add .claude/agents/journey-compiler.md .claude/agents/trajectory-skeptic.md
git commit -m "docs(dogfood): teach journey-compiler + trajectory-skeptic the GUI modality"
```

### Task 14: Docs + coverage exclusions

**Files:**
- Modify: `.claude/skills/llm-dogfooding/references/methodology.md` (replace the "Extending to the UI" stub)
- Modify: `.claude/skills/llm-dogfooding/SKILL.md` (quick-ref row)
- Modify: `sonar-project.properties` (exclude the sidecar bin + bridge from coverage)

**Interfaces:** documentation + CI-config only.

- [ ] **Step 1: Replace the "Extending to the UI" stub in `methodology.md`**

Replace the final `## Extending to the UI` paragraph with:

```markdown
## The GUI modality (Tauri app)

The same shape covers the desktop app — only Phase-2's act/observe layer swaps
(see `docs/superpowers/specs/2026-06-30-gui-dogfooding-design.md`).

- **Driver:** the cheap Actor drives the real React frontend in headless
  Chromium via `agent-browser` (Apache-2.0, pinned `v0.31.1`) called as a
  `--json` subprocess — observations are its accessibility set-of-marks
  (`[@e2] button "Create"`), actions are `{click|fill|press|select|read}`.
- **Real backend:** an in-page `real-bridge.js` forwards `invoke()` over a
  WebSocket to a headless `izba-app` sidecar (`bin/headless`, `app_lib::dispatch`)
  that reuses the app's real command/view/daemon layer against real microVMs.
- **Oracles:** daemon state-evidence + reconcile (reused), plus GUI oracles —
  `ui_daemon_diff` (UI disagrees with daemon truth), `console`, `silent_failure`,
  `dom_expect`. The UI-vs-daemon differential is the headline: it catches a UI
  that lies about state.
- **Run it:** `run_gui_journeys.py` selects `modality:"gui"` journeys; the
  `dogfood-gui` job in `dogfood.yml` fans it across KVM shards. Manual smoke:
  `hack/dogfood/gui/smoke.sh`.
- A cross-engine smoke (real WebKitGTK window via tauri-driver) is the deferred
  fidelity bump for the macro-glue/render gap.
```

- [ ] **Step 2: Add a SKILL.md quick-ref row**

In `.claude/skills/llm-dogfooding/SKILL.md`, in the "Quick reference" table, add:

```markdown
| Drive the GUI swarm (Tauri app) | `hack/dogfood/gui/run_gui_journeys.py` (agent-browser + `bin/headless` bridge); `modality:"gui"` journeys |
```

- [ ] **Step 3: Exclude the sidecar bin + bridge from coverage**

In `sonar-project.properties`, append to the single `sonar.coverage.exclusions` line (one comma-separated list — do NOT add a second `sonar.coverage.exclusions` key):

```
,app/src-tauri/src/bin/headless.rs,app/dogfood/real-bridge.js
```

(The pure logic — `dispatch`, `injectBridge`, `__dfHandleMessage` — stays covered by Tasks 7–9; only the WS/process glue and the in-page install path are excluded.)

- [ ] **Step 4: Verify the properties file still has exactly one exclusions key**

Run: `grep -c '^sonar.coverage.exclusions' sonar-project.properties`
Expected: `1`.

- [ ] **Step 5: Commit**

```bash
git add .claude/skills/llm-dogfooding/references/methodology.md .claude/skills/llm-dogfooding/SKILL.md sonar-project.properties
git commit -m "docs(dogfood): document the GUI modality + exclude bridge glue from coverage"
```

---

## Self-Review

**1. Spec coverage** (spec §-by-§ → task):
- §2 D1 reuse pipeline → Tasks 4/6 (model + loop reuse). ✅
- §2 D2 real-frontend-Chromium fidelity → Tasks 8/9/12. ✅
- §2 D3 hand-written WS sidecar reusing command/view/daemon → Task 7. ✅
- §2 D4 agent-browser driver → Task 3 + Task 12 install. ✅
- §2 D5 a11y marks not screenshots (screenshots on failure only) → Tasks 3/6. ✅
- §2 D6 fair-test boundary (app guide, no source) → Tasks 4/12/13. ✅
- §2 D7 bridge baked into the build → Task 9. ✅
- §4 GUI Actor loop + caps → Task 6. ✅
- §5 sidecar + real-bridge → Tasks 7/8. ✅
- §6 oracles (reused + 4 new + a11y discoverability via stall) → Tasks 5/6. ✅
- §7 schema + subagents → Tasks 1/2/13. ✅
- §8 CI shape → Task 12. ✅
- §9 5 skeleton journeys → Task 11. ✅
- §10 shell stubbed; agent-browser pinned; token trims; coverage exclusions → Tasks 7 (shell error)/12 (pin)/3 (caps)/14 (exclusions). ✅
- §11 component inventory → all tasks map to it. ✅
- §12 test strategy (fakes for browser + daemon; pure helpers covered) → Tasks 3–9 each lead with a fake-based unit test. ✅

**2. Placeholder scan:** No "TBD"/"add error handling"/"write tests for the above"/"similar to Task N". Each code step carries real code; each test step carries real assertions. Two explicit "verify at first CI run / at compile time" notes (agent-browser JSON shape; tungstenite 0.24 API) are diligence flags with concrete fallbacks, not missing content.

**3. Type consistency:** `Mark`, `ActResult`, `action_to_argv`, `render_marks`, `parse_snapshot` (Task 3) are consumed verbatim in Task 6. `Candidate` (oracles) reused in Task 5 + 6. `build_gui_model` (Task 4) consumed in Task 6. `dispatch(state, cmd, args, emit)` (Task 7) consumed by `bin/headless` (Task 7) and matches the WS contract `{id,cmd,args}`/`{id,ok,result|error}`/`{type:event,...}` consumed by `real-bridge.js` (Task 8) and the invoke-log shape `{cmd,ok,error}` consumed by `silent_failure_oracle` (Task 5) + `read_invoke_log` (Task 3). `injectBridge` (Task 9) and `__dfHandleMessage` (Task 8) match their tests. Journey `modality`/`source`/`steps` (Tasks 1/11) match `select_gui_journeys` + the schema. Consistent.

**Pre-confirmed during planning:** `FakeDaemon` has `impl Default` (`app/src-tauri/src/fake.rs:63`) and `izba __reconcile --json` is the correct snapshot subcommand (`oracles.py:152-157`). The only remaining compile-time reconciliation is the `tungstenite` 0.24 message API (Task 7 note) — a localized fix in `bin/headless.rs`.
