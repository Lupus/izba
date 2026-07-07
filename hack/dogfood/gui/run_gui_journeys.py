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
    Action as _A, capture_state_evidence, latency_oracle, reconcile_seq_oracle,
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
    (always has a 'violations' key).

    Report-only, but honest (mirrors oracles._snapshot_reconcile): a FAILED
    snapshot carries an ``error`` key so a broken reconciler is distinguishable
    from a clean one — a dead izba binary must not masquerade as
    ``{"violations": []}``."""
    run_env = dict(os.environ)
    if env:
        run_env.update(env)
    run_env["IZBA_DATA_DIR"] = data_dir
    err = "unknown"
    try:
        p = subprocess.run([izba_bin, "__reconcile", "--json"], capture_output=True,
                           text=True, timeout=timeout_s, env=run_env)
        if p.returncode == 0 and (p.stdout or "").strip():
            snap = json.loads(p.stdout)
            if "violations" not in snap:
                snap["violations"] = []
            return snap
        err = f"exit {p.returncode}: {(p.stderr or '')[-200:]}"
    except (OSError, subprocess.SubprocessError, ValueError) as e:
        err = repr(e)
    return {"error": err, "violations": [], "sandboxes": []}


def _settle_for_sandbox(izba_bin: str, data_dir: str, timeout_s: float,
                        action_timeout_s: float, poll_s: float = 3.0) -> None:
    """Bounded wait for an async create/VM-boot to register a sandbox before the
    final state snapshot. Polls `izba __reconcile` and returns as soon as any
    sandbox appears, or when ``timeout_s`` elapses. Report-only: never raises.
    A ``timeout_s`` of 0 returns immediately (no settle)."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        snap = _reconcile_snapshot(izba_bin, data_dir,
                                   min(action_timeout_s, max(poll_s, 1.0)))
        if snap.get("sandboxes"):
            return
        time.sleep(poll_s)


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


def _infra_candidate(journey_id: str, detail: str) -> Dict[str, Any]:
    """Flipping infra candidate — same shape as the CLI runner's (a broken
    model/driver plumbing means the journey verified nothing)."""
    return {
        "kind": "infra",
        "detail": detail,
        "violated_expectation": "model/API must produce a next command",
        "source": "harness: model transport",
        "trajectory_ref": {"journey_id": journey_id, "action_index": -1},
    }


def run_gui_journey(model, driver, journey: Dict[str, Any], *, izba_bin: str,
                    data_dir: str, max_turns: int, step_cap: int,
                    action_timeout_s: float, latency_budget_ms: int,
                    budget: Dict[str, float], max_usd: float,
                    artifact_dir: str = "",
                    create_settle_s: float = 0.0) -> Dict[str, Any]:
    """Run one GUI journey under all caps. Returns a journey_result dict.

    ``create_settle_s`` bounds an end-of-journey wait for an in-flight async
    create/VM-boot to register a sandbox in the daemon before the final
    state-evidence snapshot (the GUI ``create`` invoke resolves asynchronously,
    so a journey can otherwise end before its sandbox appears). 0 disables it
    (used by the unit tests, which mock the reconcile)."""
    journey_id = journey.get("journey_id", "")
    actions: List[Dict[str, Any]] = []
    candidates: List[Dict[str, Any]] = []
    turns = 0
    console_seen = 0
    prev_reconcile: Optional[Dict[str, Any]] = None
    steps = journey.get("steps", []) or [{"intent": journey.get("rationale", ""),
                                          "expect": ""}]
    try:
        for step in steps:
            seen: set = set()
            # Seed the Actor with the current screen so its FIRST decision sees
            # the accessibility marks (real refs to act on) rather than an empty
            # observation — otherwise it guesses a ref and burns a turn.
            marks_text = render_marks(driver.snapshot())
            obs: List[Dict[str, Any]] = [{"action": "(opened screen)",
                                          "marks": marks_text}]
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
                except Exception as e:  # report-only, but never silently green
                    log(f"{journey_id}: model error: {e!r}")
                    candidates.append(_infra_candidate(journey_id,
                                                       f"model raised: {e!r}"))
                    break
                if isinstance(reply, dict) and reply.get("error"):
                    log(f"{journey_id}: model infra error: {reply['error']}")
                    candidates.append(_infra_candidate(journey_id,
                                                       str(reply["error"])))
                    break
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
                all_console = driver.read_console_errors()
                console_errors = all_console[console_seen:]
                console_seen = len(all_console)
                action_index = len(actions)
                ref = {"journey_id": journey_id, "action_index": action_index}
                actions.append(_action_dict(step.get("intent", ""), command, res,
                                            marks_text, reconcile, console_errors))
                obs.append({"action": command, "marks": marks_text})
                # Per-action oracles.
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
                # Reconcile violations flip the journey (parity with the CLI
                # runner's _collect_candidates): declared state != reality is
                # a product finding regardless of which surface drove it.
                violations = (reconcile or {}).get("violations") or []
                if violations:
                    preview = json.dumps(violations[:3])[:400]
                    candidates.append({
                        "kind": "reconcile_violation",
                        "detail": (f"izba __reconcile reported "
                                   f"{len(violations)} violation(s) after "
                                   f"{command!r}: {preview}"),
                        "violated_expectation": "reconciler must report no "
                                                "violations (declared state == "
                                                "reality)",
                        "source": "contract: disk-state invariant (__reconcile)",
                        "trajectory_ref": dict(ref),
                    })
                prev_reconcile = reconcile
    except StopIteration:
        pass
    except BudgetExceeded:
        raise

    # Give an in-flight async create/VM-boot time to register a sandbox before
    # grading the outcome (the GUI create invoke resolves asynchronously).
    if create_settle_s > 0:
        _settle_for_sandbox(izba_bin, data_dir, create_settle_s, action_timeout_s)
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
            if actions:
                actions[-1]["screenshot_ref"] = os.path.join(
                    os.path.basename(artifact_dir), f"{journey_id}.png")
        except Exception:
            shot = ""
    for c in end_found:
        cd = c.to_dict(); cd["trajectory_ref"] = dict(final_ref)
        candidates.append(cd)
    return {"journey_id": journey_id, "actions": actions, "candidates": candidates,
            "state_evidence": state_evidence, "invoke_log": invoke_log}


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
    p.add_argument("--create-settle-s", type=float, default=90.0,
                   help="bounded end-of-journey wait for an async create/boot to "
                        "register a sandbox before grading (0 disables)")
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
                    # A dead sidecar means the journey measured NOTHING — record
                    # a flipping infra candidate so the bundle can't read as a
                    # silently-empty positive (mirrors the CLI runner's honesty).
                    log(f"{jid}: sidecar did not come up on :{ws_port}; skipping")
                    results.append({"journey_id": jid, "actions": [],
                                    "candidates": [_infra_candidate(
                                        jid, f"sidecar did not come up on "
                                             f":{ws_port}")]})
                    continue
                driver = AgentBrowserDriver(args.agent_browser_bin,
                                            http_port=http_port, ws_port=ws_port,
                                            timeout_s=args.action_timeout_s)
                driver.open(f"http://127.0.0.1:{http_port}/?ws={ws_port}")
                res = run_gui_journey(
                    model, driver, journey, izba_bin=args.izba_bin, data_dir=jdir,
                    max_turns=args.max_turns, step_cap=args.step_cap,
                    action_timeout_s=args.action_timeout_s,
                    latency_budget_ms=args.latency_budget_ms,
                    budget=budget, max_usd=args.max_usd, artifact_dir=args.artifact_dir,
                    create_settle_s=args.create_settle_s)
                driver.close()
                results.append(res)
            except BudgetExceeded:
                log("budget exhausted; stopping"); break
            except Exception as e:  # report-only, but never silently green
                log(f"journey {jid!r} crashed: {e!r}")
                results.append({"journey_id": jid, "actions": [],
                                "candidates": [_infra_candidate(
                                    jid, f"journey crashed: {e!r}")]})
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
