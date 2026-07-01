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
from dataclasses import dataclass
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
# agent-browser aria-snapshot line: `- role "name" [<attrs>, ref=eN]`. The ref
# is NOT necessarily first in the bracket (e.g. `[level=1, ref=e1]`), so match
# `ref=eN` anywhere inside the trailing `[...]`.
_ARIA_RE = re.compile(r'^\s*-\s+(?P<role>[a-zA-Z]+)\s+"(?P<name>(?:[^"\\]|\\.)*)"\s+\[[^\]]*\bref=(?P<ref>e\d+)\b')
# `[@e2] button "Create sandbox"` — render_marks output format; parse_snapshot
# must handle its own output so FakeDriver snapshots and test assertions are
# consistent (round-trip: render_marks(parse_snapshot(render_marks(marks)))==...).
_RENDER_RE = re.compile(r'^\[(?P<ref>@e\d+)\]\s+(?P<role>[a-zA-Z]+)\s+"(?P<name>(?:[^"\\]|\\.)*)"')


# Valid agent-browser subcommands accepted by AgentBrowserDriver._run.
_ALLOWED_SUBCMDS: frozenset = frozenset(
    {"open", "snapshot", "click", "fill", "press", "select",
     "eval", "screenshot", "close", "wait", "get"}
)
# Subcommands whose first positional arg is a UI element ref (@eN / eN).
_REF_SUBCMDS: frozenset = frozenset({"click", "fill", "select"})
# Element ref pattern: optional @ prefix, then 'e', then one or more digits.
_REF_RE = re.compile(r'^@?e\d+$')


def _validate_args(args: List[str]) -> Optional[str]:
    """Return an error string if *args* looks unsafe, else ``None``.

    Checks that the subcommand is in the allowlist and, for ref-taking
    commands (click / fill / select), that the element ref arg matches the
    expected ``@eN`` shape.  Other positional args (URLs, key names, text,
    JS expressions) are left unchecked as they are operator-controlled."""
    if not args:
        return "empty args list"
    subcmd = args[0]
    if subcmd not in _ALLOWED_SUBCMDS:
        return f"unknown subcommand: {subcmd!r}"
    if subcmd in _REF_SUBCMDS and len(args) > 1 and not _REF_RE.match(args[1]):
        return f"subcommand {subcmd!r}: invalid element ref {args[1]!r}"
    return None


def _norm_ref(ref: str) -> str:
    return ref if ref.startswith("@") else "@" + ref


def _marks_from_text(text: str) -> List[Mark]:
    """Parse aria-snapshot text (`- role "name" [..., ref=eN]`) OR render_marks
    output (`[@eN] role "name"`) into Marks. Unmatched lines are skipped."""
    marks: List[Mark] = []
    for line in (text or "").splitlines():
        m = _ARIA_RE.match(line)
        if m:
            marks.append(Mark(ref=_norm_ref(m.group("ref")), role=m.group("role"),
                              name=m.group("name")))
            continue
        m = _RENDER_RE.match(line)
        if m:  # ref already carries '@' in the render_marks format
            marks.append(Mark(ref=m.group("ref"), role=m.group("role"),
                              name=m.group("name")))
    return marks


def _marks_from_json(doc: Any) -> List[Mark]:
    """Build Marks from agent-browser's ``snapshot --json`` object.

    Real shape (agent-browser v0.31.x)::

        {"success": true, "data": {"refs": {"e1": {"name","role"}, ...},
                                   "snapshot": "- role \\"name\\" [ref=e1]\\n..."}}

    The ``data.refs`` dict (ref id -> {name, role}) is the primary source. Also
    tolerates a flat ``{"elements": [{"ref","role","name"}, ...]}`` list and a
    top-level ``refs`` dict (no ``data`` envelope)."""
    if isinstance(doc, list):
        items: Any = doc
    elif isinstance(doc, dict):
        data = doc.get("data") if isinstance(doc.get("data"), dict) else doc
        refs = data.get("refs")
        if isinstance(refs, dict):
            out: List[Mark] = []
            for ref, v in refs.items():
                if isinstance(v, dict):
                    out.append(Mark(ref=_norm_ref(str(ref)),
                                    role=str(v.get("role", "")),
                                    name=str(v.get("name", ""))))
            return out
        items = data.get("elements") or []
    else:
        items = []
    out2: List[Mark] = []
    for e in items:
        if isinstance(e, dict) and e.get("ref"):
            out2.append(Mark(ref=_norm_ref(str(e["ref"])), role=str(e.get("role", "")),
                             name=str(e.get("name", ""))))
    return out2


def _json_snapshot_text(doc: Any) -> str:
    """The aria-text ``snapshot`` string agent-browser embeds in its JSON, if any."""
    if isinstance(doc, dict):
        data = doc.get("data") if isinstance(doc.get("data"), dict) else doc
        s = data.get("snapshot")
        if isinstance(s, str):
            return s
    return ""


def parse_snapshot(raw: str) -> List[Mark]:
    """Parse an agent-browser snapshot into Marks. Best-effort: [] on garbage.

    Handles agent-browser's ``snapshot --json`` object (``data.refs`` dict +
    ``data.snapshot`` aria string), the plain aria-text form
    (``- role "name" [..., ref=eN]``), and render_marks' own
    ``[@eN] role "name"`` output (so FakeDriver snapshots round-trip)."""
    raw = (raw or "").strip()
    if not raw:
        return []
    if raw[0] in "{[":
        try:
            doc = json.loads(raw)
        except ValueError:
            doc = None
        marks = _marks_from_json(doc)
        if marks:
            return marks
        aria = _json_snapshot_text(doc)
        if aria:
            return _marks_from_text(aria)
        # Not usable JSON — e.g. a render_marks line `[@e1] role "name"` which
        # starts with '[' but is not JSON. Fall through to text parsing.
    return _marks_from_text(raw)


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
        self.shots: List[str] = []
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
        self.shots.append(path)

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
        err_msg = _validate_args(args)
        if err_msg:
            import logging
            logging.warning("[driver] rejected unsafe args: %s", err_msg)
            return ActResult(exit_code=1, stdout="",
                             stderr=f"validation error: {err_msg}", latency_ms=0)
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
