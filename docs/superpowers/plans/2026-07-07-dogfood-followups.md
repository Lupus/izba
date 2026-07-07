# Dogfood Instrument-Honesty Follow-ups Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the four accepted-non-blocking follow-ups of PR #127: GUI catastrophic-infra exit-3 backstop, CLI-side modality filtering (+ `has_cli` job skip), the agent-browser eval-envelope fix (empty `invoke_log`/console errors on real GUI runs), and the collector's per-modality `by_kind` split.

**Architecture:** Four independent, small TDD changes to the stdlib-only Python dogfood harness (`hack/dogfood/`), one workflow edit (`.github/workflows/dogfood.yml`), and two doc touch-ups. Spec: `docs/superpowers/specs/2026-07-07-dogfood-followups-design.md`.

**Tech Stack:** Python 3 stdlib only (pytest to run the suite — tests are plain `unittest` in `hack/dogfood/test_runner.py` and pytest-style functions in `hack/dogfood/gui/test_*.py`; follow whichever style the target file already uses). GitHub Actions YAML.

## Global Constraints

- Python: **stdlib only** in `hack/dogfood/` (no new deps; `jsonschema` stays optional/report-only).
- Test command for everything here: `python3 -m pytest hack/dogfood/ -q` (baseline on main: 158 passed). Run it from the worktree root.
- The GUI runner and its tests import via `sys.path.insert(0, <hack/dogfood>)` — run pytest from the repo root so relative fixture paths resolve.
- **Sandbox gotcha:** `.claude/skills/` may be read-only for sandboxed Bash. Edit `.claude/skills/llm-dogfooding/scripts/collect-trajectories.py` with the **Edit tool** (not shell redirection); if a Bash-based step on that path fails with EPERM/read-only, retry that command with the sandbox disabled.
- Conventional commits (`fix(dogfood): ...`, `feat(dogfood): ...`, `docs(dogfood): ...`); every commit message ends with the `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>` trailer.
- No trajectory-schema changes; `by_kind_by_modality` is **additive** in the collector output only.

---

### Task 1: CLI runner filters out `modality:"gui"` journeys

**Files:**
- Modify: `hack/dogfood/run_journeys.py` (add `select_cli_journeys` next to `select_shard` ~line 85; use it in `main()` ~line 613)
- Test: `hack/dogfood/test_runner.py` (extend `ShardSelectionTests`, ~line 60)

**Interfaces:**
- Produces: `select_cli_journeys(journeys: List[Dict[str, Any]]) -> List[Dict[str, Any]]` — keeps journeys whose `modality != "gui"`. (Mirror of `gui/run_gui_journeys.py::select_gui_journeys`, which keeps only `== "gui"`.)
- Consumes: nothing new.

- [ ] **Step 1: Write the failing tests**

Add to `hack/dogfood/test_runner.py`, inside `class ShardSelectionTests` (after `test_shard_selects_modulo`):

```python
    def test_select_cli_journeys_excludes_gui(self):
        js = [{"journey_id": "c1"},
              {"journey_id": "g1", "modality": "gui"},
              {"journey_id": "c2", "modality": "cli"}]
        self.assertEqual(
            [j["journey_id"] for j in run_journeys.select_cli_journeys(js)],
            ["c1", "c2"])

    def test_main_excludes_gui_journeys_from_cli_shards(self):
        # A CLI shard must never run a modality:"gui" journey as CLI — in the
        # gui-skeleton dispatch the model typed shell commands at GUI intents.
        with tempfile.TemporaryDirectory() as d:
            stub = _write_stub_izba(d)
            jf = _journeys_file(d, [
                {"journey_id": "cli-j", "rationale": "r",
                 "source": {"kind": "spec", "ref": "x"},
                 "steps": [{"intent": "do", "expect": "works"}]},
                {"journey_id": "gui-j", "modality": "gui", "rationale": "r",
                 "source": {"kind": "spec", "ref": "x"},
                 "steps": [{"intent": "click it", "expect": "works"}]},
            ])
            out = os.path.join(d, "traj.json")
            script = [{"command": "izba ls"}, {"done": True}]
            rc = run_journeys.main([
                "--journeys", jf, "--shard", "0", "--shards", "1",
                "--izba-bin", stub, "--data-dir", d, "--out", out,
                "--fake-model", json.dumps(script)])
            self.assertEqual(rc, 0)
            with open(out) as f:
                bundle = json.load(f)
            self.assertEqual([r["journey_id"] for r in bundle["results"]],
                             ["cli-j"])
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest hack/dogfood/test_runner.py -q -k "select_cli or excludes_gui"`
Expected: 2 FAIL/ERROR — `AttributeError: ... has no attribute 'select_cli_journeys'`, and the main test asserts `["cli-j"]` but gets `["cli-j", "gui-j"]`.

- [ ] **Step 3: Implement**

In `hack/dogfood/run_journeys.py`, directly after `select_shard` (~line 90):

```python
def select_cli_journeys(journeys: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """CLI-modality journeys only — the mirror of the GUI runner's
    select_gui_journeys. A CLI shard must never run a modality:"gui" journey
    as if it were CLI (the model would type shell commands at a GUI intent)."""
    return [j for j in journeys if j.get("modality") != "gui"]
```

In `main()` (~line 613), replace:

```python
    all_journeys = doc.get("journeys", []) or []
    mine = select_shard(all_journeys, args.shard, args.shards)
    log(f"shard {args.shard}/{args.shards}: {len(mine)} of {len(all_journeys)} journeys")
```

with:

```python
    all_journeys = doc.get("journeys", []) or []
    cli_journeys = select_cli_journeys(all_journeys)
    mine = select_shard(cli_journeys, args.shard, args.shards)
    log(f"shard {args.shard}/{args.shards}: {len(mine)} of {len(cli_journeys)} "
        f"cli journeys ({len(all_journeys) - len(cli_journeys)} gui excluded)")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest hack/dogfood/test_runner.py -q`
Expected: all pass (no other test in the file feeds `modality:"gui"` journeys to `main`).

- [ ] **Step 5: Commit**

```bash
git add hack/dogfood/run_journeys.py hack/dogfood/test_runner.py
git commit -m "fix(dogfood): CLI shards no longer run modality:gui journeys

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: GUI runner catastrophic-infra exit-3 backstop

**Files:**
- Modify: `hack/dogfood/gui/run_gui_journeys.py` (import line ~32; `main()` tail ~lines 425–429)
- Modify: `hack/dogfood/gui/test_run_gui_journeys.py` (existing `test_sidecar_startup_failure_records_infra_candidate` ~line 203; new tests after it)
- Modify: `hack/dogfood/local-harness.md` (§1.4, ~line 140)
- Modify: `docs/dogfooding-value.md` (§ "infra candidates + exit 3" wording, ~line 159)

**Interfaces:**
- Consumes: `CATASTROPHIC_DEGRADED_FRACTION` (0.5) and `EXIT_CATASTROPHIC_INFRA` (3) from `run_journeys` (the GUI runner already imports `select_shard`, `_journey_data_dir`, `BudgetExceeded` from it — extend that import, do NOT re-declare the constants).
- Produces: `gui/run_gui_journeys.py::main()` returns `EXIT_CATASTROPHIC_INFRA` when `degraded/len(results) > 0.5` (strictly), 0 otherwise; zero attempted journeys is NOT catastrophic; the bundle is written before the exit decision.

- [ ] **Step 1: Update the existing sidecar test + write the new failing tests**

In `hack/dogfood/gui/test_run_gui_journeys.py`, change the tail of `test_sidecar_startup_failure_records_infra_candidate` — replace:

```python
    assert rc == 0  # report-only
```

with:

```python
    # 1/1 journeys degraded -> catastrophic backstop, same contract as the CLI
    # runner: a dead sidecar on every journey is a run that measured nothing.
    assert rc == rgj.EXIT_CATASTROPHIC_INFRA
```

(the bundle-content assertions below it stay — they prove the bundle is written even on exit 3).

Then append these tests at the end of the file:

```python
def test_gui_exactly_half_degraded_is_not_catastrophic(monkeypatch, tmp_path):
    # Pin the boundary: 1 of 2 degraded is 0.5, NOT > 0.5 -> rc 0. Kills a
    # `>` -> `>=` mutation, mirrors the CLI runner's boundary test.
    import gui.run_gui_journeys as rgj

    class _DummyProc:
        def terminate(self):
            pass

        def wait(self, timeout=None):
            return 0

        def kill(self):
            pass

    canned = {
        "healthy": {"journey_id": "healthy",
                    "actions": [{"command": "click @e1", "exit_code": 0}],
                    "candidates": []},
        "degraded": {"journey_id": "degraded", "actions": [],
                     "candidates": [rgj._infra_candidate("degraded",
                                                         "model error")]},
    }
    monkeypatch.setattr(rgj, "_spawn_sidecar", lambda *a, **k: _DummyProc())
    monkeypatch.setattr(rgj, "_wait_port", lambda *a, **k: True)
    monkeypatch.setattr(rgj, "AgentBrowserDriver",
                        lambda *a, **k: FakeDriver(snapshots=[]))
    monkeypatch.setattr(
        rgj, "run_gui_journey",
        lambda model, driver, journey, **k: canned[journey["journey_id"]])
    journeys = {"feature": "f", "journeys": [
        {"journey_id": jid, "modality": "gui", "rationale": "r",
         "source": {"kind": "spec", "ref": "x"},
         "steps": [{"intent": "do", "expect": ""}]}
        for jid in ("healthy", "degraded")]}
    jf = tmp_path / "journeys.json"
    jf.write_text(__import__("json").dumps(journeys))
    out = tmp_path / "gui-traj-0.json"
    rc = rgj.main([
        "--journeys", str(jf), "--shard", "0", "--shards", "1",
        "--izba-bin", "izba", "--sidecar-bin", "/nonexistent/sidecar",
        "--frontend-dir", str(tmp_path), "--data-dir", str(tmp_path / "d"),
        "--out", str(out), "--fake-model", "[]"])
    assert rc == 0
    bundle = __import__("json").loads(out.read_text())
    assert {r["journey_id"] for r in bundle["results"]} == {"healthy", "degraded"}


def test_gui_zero_attempted_journeys_is_not_catastrophic(tmp_path):
    # An all-CLI corpus sharded to the GUI runner measures nothing BY DESIGN:
    # empty `results` must not trip the backstop.
    import gui.run_gui_journeys as rgj

    journeys = {"feature": "f", "journeys": [
        {"journey_id": "cli-only", "rationale": "r",
         "source": {"kind": "spec", "ref": "x"},
         "steps": [{"intent": "do", "expect": ""}]}]}
    jf = tmp_path / "journeys.json"
    jf.write_text(__import__("json").dumps(journeys))
    out = tmp_path / "gui-traj-0.json"
    rc = rgj.main([
        "--journeys", str(jf), "--shard", "0", "--shards", "1",
        "--izba-bin", "izba", "--sidecar-bin", "/nonexistent/sidecar",
        "--frontend-dir", str(tmp_path), "--data-dir", str(tmp_path / "d"),
        "--out", str(out), "--fake-model", "[]"])
    assert rc == 0
    bundle = __import__("json").loads(out.read_text())
    assert bundle["results"] == []
```

(`FakeDriver` is already imported at the top of this test file.)

- [ ] **Step 2: Run tests to verify the right ones fail**

Run: `python3 -m pytest hack/dogfood/gui/test_run_gui_journeys.py -q`
Expected: `test_sidecar_startup_failure_records_infra_candidate` FAILS (`AttributeError: module ... has no attribute 'EXIT_CATASTROPHIC_INFRA'`); the two new tests PASS already (they exercise rc-0 paths) — that is fine, they pin the boundary against the change in Step 3.

- [ ] **Step 3: Implement**

In `hack/dogfood/gui/run_gui_journeys.py`, extend the existing import (~line 32):

```python
from run_journeys import (  # noqa: E402
    select_shard, _journey_data_dir, BudgetExceeded,
    CATASTROPHIC_DEGRADED_FRACTION, EXIT_CATASTROPHIC_INFRA,
)
```

Replace the `main()` tail (currently the bundle write + `return 0`, ~lines 425–429):

```python
    bundle = {"shard": args.shard, "feature": feature, "results": results}
    with open(args.out, "w") as f:
        json.dump(bundle, f, indent=2)
    # Same catastrophic-infra backstop as the CLI runner: when more than half
    # the attempted journeys are degraded (zero actions, or >=1 infra
    # candidate), the run measured nothing and must not read as a green void.
    # Zero attempted journeys is NOT catastrophic (an all-CLI corpus sharded
    # to a GUI runner measures nothing by design). The bundle is written
    # first so a catastrophic run's trajectories stay inspectable.
    degraded = sum(
        1 for r in results
        if not r.get("actions")
        or any(c.get("kind") == "infra" for c in r.get("candidates", []))
    )
    catastrophic = (bool(results)
                    and degraded / len(results) > CATASTROPHIC_DEGRADED_FRACTION)
    log(f"wrote {args.out}: {len(results)} journeys ({degraded} degraded), "
        f"est. ${budget['usd']:.4f}")
    if catastrophic:
        log(f"CATASTROPHIC: {degraded}/{len(results)} gui journeys degraded "
            f"(> {CATASTROPHIC_DEGRADED_FRACTION:.0%}) — the run measured "
            f"nothing; failing the job (exit {EXIT_CATASTROPHIC_INFRA})")
        return EXIT_CATASTROPHIC_INFRA
    return 0
```

No module-attribute alias is needed — the test reads `rgj.EXIT_CATASTROPHIC_INFRA`, which the `from run_journeys import ...` line provides.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest hack/dogfood/gui/ -q`
Expected: all pass.

- [ ] **Step 5: Update the two docs**

`hack/dogfood/local-harness.md` §1.4: replace the sentence

> The run is **report-only**: findings never fail a shard. `run_journeys.py` exits
> distinguish "ran" from "couldn't measure", so a CI shard fails loudly only when
> the run was not a measurement:

with

> The run is **report-only**: findings never fail a shard. Both runners
> (`run_journeys.py` and `gui/run_gui_journeys.py`) use the same exit codes to
> distinguish "ran" from "couldn't measure", so a CI shard fails loudly only when
> the run was not a measurement:

`docs/dogfooding-value.md`: in the "**`infra` candidates + exit 3:**" sentence, replace

> and when more than half a run's journeys are degraded the
> runner exits with a distinct code (`3`) so the CI shard fails loudly rather than
> reporting a green void.

with

> and when more than half a run's journeys are degraded the
> runner — CLI and GUI alike — exits with a distinct code (`3`) so the CI shard
> fails loudly rather than reporting a green void.

- [ ] **Step 6: Run the full suite and commit**

Run: `python3 -m pytest hack/dogfood/ -q`
Expected: all pass.

```bash
git add hack/dogfood/gui/run_gui_journeys.py hack/dogfood/gui/test_run_gui_journeys.py hack/dogfood/local-harness.md docs/dogfooding-value.md
git commit -m "fix(dogfood): GUI runner gets the catastrophic-infra exit-3 backstop

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: `_eval_json` unwraps the agent-browser `--json` envelope

**Files:**
- Modify: `hack/dogfood/gui/driver.py` (`AgentBrowserDriver._eval_json`, ~lines 273–287)
- Test: `hack/dogfood/gui/test_driver.py` (append)

**Interfaces:**
- Produces: `_eval_json` unwrap order: dict with dict `data` containing `result` → `data["result"]`; other dict → `doc.get("result", doc)`; non-dict → itself; a string value still gets a second `json.loads` pass. `read_invoke_log()`/`read_console_errors()` unchanged on top.
- Consumes: `ActResult` dataclass from `driver.py` (fields `exit_code, stdout, stderr, latency_ms`).

**Background (why):** real `agent-browser eval --json` (probed on 0.25.4; `parse_snapshot` already handles the same `data.*` envelope for the CI-pinned 0.31.1) returns
`{"success":true,"data":{"origin":"<url>","result":<value-or-JSON-string>},"error":null}`.
The current code only unwraps a top-level `result`, so it returns the whole envelope dict and `read_invoke_log()`/`read_console_errors()` collapse to `[]` on every real run.

- [ ] **Step 1: Write the failing tests**

Append to `hack/dogfood/gui/test_driver.py`:

```python
def _stub_driver(stdout):
    """AgentBrowserDriver whose _run returns canned stdout (no subprocess)."""
    from gui.driver import ActResult, AgentBrowserDriver
    d = AgentBrowserDriver("agent-browser", http_port=0, ws_port=0)
    d._run = lambda args: ActResult(exit_code=0, stdout=stdout, stderr="",
                                    latency_ms=0)
    return d


def test_eval_json_unwraps_real_agent_browser_envelope_string_result():
    # Real `agent-browser eval --json` output: the value sits under
    # data.result as a JSON string (probed on 0.25.4; same envelope family as
    # snapshot's data.refs on 0.31.1). The old code returned the whole
    # envelope dict, so read_invoke_log() was [] on every real run.
    out = ('{"success":true,"data":{"origin":"http://127.0.0.1:1",'
           '"result":"[{\\"cmd\\":\\"list_sandboxes\\",\\"ok\\":true,'
           '\\"error\\":\\"\\"}]"},"error":null}')
    d = _stub_driver(out)
    assert d.read_invoke_log() == [
        {"cmd": "list_sandboxes", "ok": True, "error": ""}]


def test_eval_json_unwraps_real_agent_browser_envelope_raw_result():
    out = ('{"success":true,"data":{"origin":"http://127.0.0.1:1",'
           '"result":[{"cmd":"a","ok":true}]},"error":null}')
    d = _stub_driver(out)
    assert d._eval_json("whatever") == [{"cmd": "a", "ok": True}]


def test_eval_json_still_handles_legacy_top_level_result():
    d = _stub_driver('{"result": "[1, 2]"}')
    assert d._eval_json("whatever") == [1, 2]


def test_eval_json_bare_value_and_garbage():
    assert _stub_driver('["x"]')._eval_json("e") == ["x"]
    assert _stub_driver("not json")._eval_json("e") is None


def test_read_console_errors_through_real_envelope():
    out = ('{"success":true,"data":{"origin":"o",'
           '"result":"[\\"boom\\"]"},"error":null}')
    assert _stub_driver(out).read_console_errors() == ["boom"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest hack/dogfood/gui/test_driver.py -q`
Expected: the three envelope tests FAIL (invoke log `[]`, `_eval_json` returning the envelope dict); the legacy/bare tests PASS.

- [ ] **Step 3: Implement**

In `hack/dogfood/gui/driver.py`, replace the body of `_eval_json` after the `json.loads` try/except:

```python
    def _eval_json(self, expr: str) -> Any:
        out = self._run(["eval", expr]).stdout.strip()
        # agent-browser --json wraps eval results in
        # {"success":..,"data":{"origin":..,"result":<value-or-json-string>}};
        # tolerate the legacy top-level {"result": ...} and a bare JSON value.
        try:
            doc = json.loads(out)
        except ValueError:
            return None
        val = doc
        if isinstance(doc, dict):
            data = doc.get("data")
            if isinstance(data, dict) and "result" in data:
                val = data["result"]
            else:
                val = doc.get("result", doc)
        if isinstance(val, str):
            try:
                return json.loads(val)
            except ValueError:
                return val
        return val
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest hack/dogfood/gui/ -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add hack/dogfood/gui/driver.py hack/dogfood/gui/test_driver.py
git commit -m "fix(dogfood): unwrap the agent-browser eval envelope (empty invoke_log on real GUI runs)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: collector `totals.by_kind_by_modality`

**Files:**
- Modify: `.claude/skills/llm-dogfooding/scripts/collect-trajectories.py` (`collect()` ~lines 72–137; summary print in `main()` ~line 152). **Use the Edit tool — this path can be read-only for sandboxed Bash.**
- Test: `hack/dogfood/test_runner.py` (`CollectorBucketsTests`, ~line 896)

**Interfaces:**
- Produces: additive `totals["by_kind_by_modality"]: {"cli": {kind: n}, "gui": {kind: n}}` — only modalities that occur appear as keys; the flat `totals["by_kind"]` is unchanged.
- Consumes: `modality` is already computed per bundle (`"gui" if basename startswith "gui-" else "cli"`).

- [ ] **Step 1: Write the failing test**

Add to `CollectorBucketsTests` in `hack/dogfood/test_runner.py`:

```python
    def test_by_kind_split_by_modality(self):
        collector = _load_collector()
        if collector is None:
            self.skipTest("collector script not present")
        with tempfile.TemporaryDirectory() as d:
            self._mk_bundle(d, "traj-0.json", [
                {"journey_id": "cli-dead", "actions": [], "candidates": [
                    {"kind": "infra", "detail": "x", "violated_expectation": "",
                     "source": "", "trajectory_ref": {"journey_id": "cli-dead",
                                                      "action_index": -1}}]}])
            self._mk_bundle(d, "gui-traj-0.json", [
                {"journey_id": "gui-err", "actions": [], "candidates": [
                    {"kind": "console", "detail": "boom",
                     "violated_expectation": "", "source": "",
                     "trajectory_ref": {"journey_id": "gui-err",
                                        "action_index": 0}}]}])
            data = collector.collect(d)
            self.assertEqual(data["totals"]["by_kind"],
                             {"infra": 1, "console": 1})
            self.assertEqual(data["totals"]["by_kind_by_modality"],
                             {"cli": {"infra": 1}, "gui": {"console": 1}})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest hack/dogfood/test_runner.py -q -k by_kind_split`
Expected: FAIL with `KeyError: 'by_kind_by_modality'`.

- [ ] **Step 3: Implement**

In `collect()`: after `by_kind = collections.Counter()` add

```python
    by_kind_by_modality: dict = {}
```

inside the `for c in cands:` loop, right after `by_kind[...] += 1`, add

```python
                by_kind_by_modality.setdefault(
                    modality, collections.Counter())[c.get("kind", "?")] += 1
```

and in the returned `totals` dict, after the `"by_kind"` entry, add

```python
                   "by_kind_by_modality": {
                       m: dict(cnt) for m, cnt in by_kind_by_modality.items()},
```

In `main()`, after the `== ... ==` header print, add the split when more than one modality occurred:

```python
    if len(t.get("by_kind_by_modality", {})) > 1:
        for m, kinds in sorted(t["by_kind_by_modality"].items()):
            print(f"   {m}: {kinds}")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest hack/dogfood/test_runner.py -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add .claude/skills/llm-dogfooding/scripts/collect-trajectories.py hack/dogfood/test_runner.py
git commit -m "feat(dogfood): collector splits by_kind per modality

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 5: `dogfood.yml` gains the symmetric `has_cli` skip

**Files:**
- Modify: `.github/workflows/dogfood.yml` (setup job outputs ~line 71; the `id: plan` python heredoc ~line 106; the `dogfood` job header ~line 255; the setup-job comment ~line 63)

**Interfaces:**
- Produces: `needs.setup.outputs.has_cli` (`'true'`/`'false'`); the `dogfood` (CLI) job is skipped when the journey set has no CLI journeys. Both swarm jobs are terminal in the job graph (nothing `needs:` them), so skipping is safe.
- Consumes: `n_cli` (already computed in the setup python).

- [ ] **Step 1: Edit the workflow**

1. In the `setup:` job `outputs:` block, after `has_gui: ...`, add:

```yaml
      has_cli: ${{ steps.plan.outputs.has_cli }}
```

2. In the python heredoc, after the `has_gui=` write, add:

```python
              f.write(f"has_cli={'true' if n_cli else 'false'}\n")
```

3. On the `dogfood:` job (the CLI swarm), directly under its `needs: [setup, kernel, initramfs]` line, add:

```yaml
    if: needs.setup.outputs.has_cli == 'true'
```

4. Update the setup-job comment (the "GUI jobs are skipped entirely…" sentence) to:

```yaml
  # Derive the shard matrices from the inputs + the journey set, so the shard
  # count is a real knob (the old hardcoded 3-shard matrices killed dispatches
  # with any other value) and each modality's jobs are skipped entirely when
  # the set has no journeys for it (3 wasted Tauri builds / a wasted KVM shard
  # matrix otherwise). Both swarm jobs are terminal (nothing `needs:` them),
  # so skipping is safe.
```

- [ ] **Step 2: Verify the YAML parses**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/dogfood.yml')); print('ok')"`
Expected: `ok` (if PyYAML is missing, `pip install --user pyyaml` or fall back to `ruby -ryaml -e "YAML.load_file('.github/workflows/dogfood.yml'); puts 'ok'"`).

Also eyeball: `grep -n "has_cli\|has_gui" .github/workflows/dogfood.yml` shows the output wired in `outputs:`, written in the heredoc, and consumed by exactly one `if:` on the `dogfood` job (plus the existing `has_gui` trio).

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/dogfood.yml
git commit -m "ci(dogfood): skip the CLI swarm job for all-GUI journey sets

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 6: full-suite verification

**Files:** none new.

- [ ] **Step 1: Run the whole dogfood suite**

Run: `python3 -m pytest hack/dogfood/ -q`
Expected: everything passes (baseline was 158; this plan adds ~10 tests).

- [ ] **Step 2: Sanity-run both runners end-to-end with the fake model**

```bash
python3 hack/dogfood/run_journeys.py --journeys hack/dogfood/journeys/smoke-core-cli.json \
  --shard 0 --shards 1 --izba-bin /bin/true --data-dir /tmp/claude/dfchk \
  --out /tmp/claude/dfchk/traj-0.json --fake-model '[{"done": true}]' ; echo "cli rc=$?"
```

Expected: the shard log line reports `... cli journeys (0 gui excluded)`; rc is 0 or 3 (with a single-reply fake script most journeys degrade — either is fine, we only care that it runs and the log line shape is right).

- [ ] **Step 3: Nothing to commit** (verification only). If anything failed, fix within the owning task's files and amend that task's commit.
