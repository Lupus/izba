# Dogfood Instrument Honesty Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the LLM-dogfood harness's greens trustworthy (no silent-green paths), fix the CI evidence plumbing, add the standing smoke corpus + weekly run, and align the skill/agents/docs with the owner-locked placement model.

**Architecture:** All harness changes are pure-Python in `hack/dogfood/` (stdlib only, covered by the existing pytest CI gate). New candidate kinds flow through the existing Candidate → bundle → collector pipeline, which fails loud on unknown kinds by design. CI changes replace hardcoded shard matrices with a generator ("setup") job. Skill/docs changes encode the value model and the new mechanics.

**Tech Stack:** Python 3 stdlib (+ optional `jsonschema`), GitHub Actions YAML, JSON Schema draft-07, markdown.

**Spec:** `docs/superpowers/specs/2026-07-04-dogfood-instrument-honesty-design.md` (approved). Read it before starting any task.

## Global Constraints

- Python: stdlib only in `hack/dogfood/` (`jsonschema` is optional-import, report-only when absent).
- TDD: every behavior change lands test-first. Test suite: `python3 -m pytest hack/dogfood/ -q` (this is a required CI gate).
- The runner stays **report-only for findings**: findings never change the exit code. The ONLY new non-zero exit is the catastrophic-infra one (exit **3**, >50% degraded journeys).
- Never break the bundle contract silently: every new candidate kind is added to `hack/dogfood/schema/trajectory.schema.json` in the same task that emits it… except where a task explicitly defers to Task 7 (which syncs schemas + adds write-time validation).
- New candidate kinds (exact strings): `infra`, `unreached_decisive`, `reconcile_violation`, `guest_console`.
- Conventional commits (`feat(dogfood): …`, `fix(ci): …`, `docs(dogfood): …`), each ending with:
  `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`
- No Rust changes anywhere in this plan. Do not touch `app/` (the GUI fixes are Python-side in `hack/dogfood/gui/`).
- Worktree: `/home/kolkhovskiy/git/izba/.claude/worktrees/dogfood-instrument-honesty` on branch `worktree-dogfood-instrument-honesty` (already exists, spec + plan committed).
- The collector script lives OUT of `hack/dogfood/`: `.claude/skills/llm-dogfooding/scripts/collect-trajectories.py`. Its tests live in `hack/dogfood/test_runner.py` via the `_load_collector()` loader (test_runner.py:20-34); follow that pattern for the new `append-ledger.py`.

---

### Task 1: model.py returns `{"error": …}` on failure + test_model.py

**Files:**
- Modify: `hack/dogfood/model.py`
- Create: `hack/dogfood/test_model.py`

**Interfaces:**
- Produces: `OpenRouterModel.next_command()` and `_parse_reply()` may now return `{"error": "<reason>"}` (a dict with a non-empty string under `"error"`). Task 2's runner consumes this shape. `{"done": true}` now ONLY means the model chose to finish.

- [ ] **Step 1: Write the failing tests**

Create `hack/dogfood/test_model.py`:

```python
"""Tests for the OpenRouter model layer: retries, error surfacing, cost.

The HTTP boundary is faked by monkeypatching urllib.request.urlopen — no
network, no API key. This was previously the only untested module."""
import io
import json
import os
import sys
import unittest
import urllib.error
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import model  # noqa: E402
from model import OpenRouterModel, _parse_reply  # noqa: E402


def _ok_response(content, usage=None):
    body = {"choices": [{"message": {"content": content}}]}
    if usage is not None:
        body["usage"] = usage
    raw = json.dumps(body).encode("utf-8")

    class _Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    return _Resp(raw)


JOURNEY = {"journey_id": "j"}
STEP = {"intent": "i", "expect": "e"}


class ParseReplyTests(unittest.TestCase):
    def test_valid_command(self):
        self.assertEqual(_parse_reply('{"command": "izba ls"}'),
                         {"command": "izba ls"})

    def test_done(self):
        self.assertEqual(_parse_reply('{"done": true}'), {"done": True})

    def test_json_embedded_in_prose(self):
        out = _parse_reply('Sure!\n```json\n{"command": "izba ls"}\n```')
        self.assertEqual(out, {"command": "izba ls"})

    def test_malformed_is_error_not_done(self):
        out = _parse_reply("I think you should run izba ls")
        self.assertIn("error", out)
        self.assertNotIn("done", out)

    def test_wrong_shape_is_error_not_done(self):
        out = _parse_reply('{"commands": ["a", "b"]}')
        self.assertIn("error", out)


class NextCommandTests(unittest.TestCase):
    def _model(self, **kw):
        kw.setdefault("retry_backoff_s", 0.0)
        return OpenRouterModel("key", "some/model", **kw)

    def test_success_first_try(self):
        with mock.patch.object(model.urllib.request, "urlopen",
                               return_value=_ok_response('{"command": "izba ls"}')):
            out = self._model().next_command(JOURNEY, STEP, [])
        self.assertEqual(out, {"command": "izba ls"})

    def test_retry_then_success(self):
        calls = {"n": 0}

        def flaky(req, timeout):
            calls["n"] += 1
            if calls["n"] == 1:
                raise urllib.error.URLError("boom")
            return _ok_response('{"done": true}')

        with mock.patch.object(model.urllib.request, "urlopen", side_effect=flaky):
            out = self._model().next_command(JOURNEY, STEP, [])
        self.assertEqual(out, {"done": True})
        self.assertEqual(calls["n"], 2)

    def test_retry_exhaustion_is_error_not_done(self):
        err = urllib.error.URLError("connection refused")
        with mock.patch.object(model.urllib.request, "urlopen", side_effect=err):
            out = self._model(max_retries=1).next_command(JOURNEY, STEP, [])
        self.assertIn("error", out)
        self.assertNotIn("done", out)
        self.assertIn("connection refused", out["error"])

    def test_missing_content_is_error(self):
        with mock.patch.object(model.urllib.request, "urlopen",
                               return_value=_ok_response(None)) as m:
            # body with no usable content: choices[0].message.content = None
            out = self._model().next_command(JOURNEY, STEP, [])
        # None content parses as empty -> _parse_reply("") -> error
        self.assertIn("error", out)

    def test_cost_prefers_usage_cost(self):
        resp = _ok_response('{"done": true}', usage={"cost": 0.0123,
                                                     "total_tokens": 999999})
        with mock.patch.object(model.urllib.request, "urlopen", return_value=resp):
            m = self._model()
            m.next_command(JOURNEY, STEP, [])
        self.assertAlmostEqual(m.last_cost_usd, 0.0123)

    def test_cost_falls_back_to_tokens(self):
        resp = _ok_response('{"done": true}', usage={"total_tokens": 2_000_000})
        with mock.patch.object(model.urllib.request, "urlopen", return_value=resp):
            m = self._model()
            m.next_command(JOURNEY, STEP, [])
        self.assertAlmostEqual(m.last_cost_usd,
                               2.0 * model.APPROX_USD_PER_1M_TOKENS)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest hack/dogfood/test_model.py -q`
Expected: FAIL — `test_malformed_is_error_not_done`, `test_wrong_shape_is_error_not_done`, `test_retry_exhaustion_is_error_not_done`, `test_missing_content_is_error` fail (current code returns `{"done": True}`); the others pass.

- [ ] **Step 3: Implement the error returns in `model.py`**

In `_parse_reply` (model.py:94-109), replace the three `{"done": True}` fallbacks that represent FAILURE (keep the legitimate-shape path intact):

```python
def _parse_reply(content: str) -> Dict[str, Any]:
    """Extract the {"command": ...} | {"done": true} object from model content.

    A reply we cannot parse is an INFRA ERROR, not a completion: returning
    {"done": true} here made a broken model indistinguishable from a finished
    step (the silent-green path). The runner turns {"error": ...} into a
    flipping `infra` candidate."""
    content = content.strip()
    try:
        obj = json.loads(content)
    except ValueError:
        m = _JSON_OBJ_RE.search(content)
        if not m:
            return {"error": f"unparseable model reply: {content[:120]!r}"}
        try:
            obj = json.loads(m.group(0))
        except ValueError:
            return {"error": f"unparseable model reply: {content[:120]!r}"}
    if isinstance(obj, dict) and (obj.get("done") or obj.get("read")
                                  or isinstance(obj.get("command"), str)):
        return obj
    return {"error": f"model reply has wrong shape: {content[:120]!r}"}
```

(Note the added `obj.get("read")` arm: the GUI reply parser wraps this one — `gui_model.py` has its own parser, but keep `_parse_reply` tolerant of a `read` key so the shapes stay compatible.)

In `OpenRouterModel.next_command` (model.py:199-217), surface transport failures:

```python
        body = None
        last_err = ""
        for attempt in range(self._max_retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                    body = json.loads(resp.read().decode("utf-8"))
                break
            except (urllib.error.URLError, ValueError, OSError) as e:
                last_err = str(e)
                if attempt >= self._max_retries:
                    return {"error": (f"openrouter request failed after "
                                      f"{attempt + 1} attempts: {last_err}")}
                time.sleep(self._retry_backoff_s * (attempt + 1))
        if body is None:
            return {"error": f"openrouter request failed: {last_err or 'no body'}"}

        self.last_cost_usd = self._estimate_cost(body)
        try:
            content = body["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            return {"error": "openrouter reply missing choices[0].message.content"}
        return self._reply_parser(content or "")
```

Also update the module docstring (model.py:12-15) and the class docstring (model.py:149): the reply contract is now `{"command"} | {"done"} | {"error"}` and the class is no longer "on error returns done".

- [ ] **Step 4: Run the full dogfood suite**

Run: `python3 -m pytest hack/dogfood/ -q`
Expected: test_model.py PASSES. **Some existing tests may fail** if they relied on malformed-reply→done; fix only by updating those tests' *expectations* if the new behavior is correct per spec §3.1 (likely none fail: FakeModel doesn't go through `_parse_reply`, and the GUI model has its own parser).

- [ ] **Step 5: Commit**

```bash
git add hack/dogfood/model.py hack/dogfood/test_model.py
git commit -m "feat(dogfood): surface model/API failures as {\"error\"} instead of fake done

A dead API key, retry exhaustion, or an unparseable reply previously
collapsed into {\"done\": true} -> zero-action journeys tallied POSITIVE
(silent-green path #1 from the 2026-07-04 spec). Also first-ever tests
for the OpenRouter layer (urlopen seam).

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: runner turns `{"error"}` into flipping `infra` candidates + catastrophic exit 3 + model default

**Files:**
- Modify: `hack/dogfood/run_journeys.py`
- Test: `hack/dogfood/test_runner.py` (append a new test class)

**Interfaces:**
- Consumes: Task 1's `{"error": …}` reply shape.
- Produces: candidate dicts `{"kind": "infra", "detail": <reason>, "violated_expectation": "model/API must produce a next command", "source": "harness: model transport", "trajectory_ref": {"journey_id": jid, "action_index": -1}}`. `main()` returns **3** when >50% of attempted journeys are degraded (zero actions OR ≥1 infra candidate). Module constant `CATASTROPHIC_DEGRADED_FRACTION = 0.5`.

- [ ] **Step 1: Write the failing tests** (append to `hack/dogfood/test_runner.py`)

```python
class InfraCandidateTests(unittest.TestCase):
    def _run(self, d, fake_script, n_journeys=1):
        stub = _write_stub_izba(d)
        journeys = [{
            "journey_id": f"j{i}", "rationale": "r",
            "source": {"kind": "spec", "ref": "x"},
            "steps": [{"intent": "do", "expect": "works"}],
        } for i in range(n_journeys)]
        jf = _journeys_file(d, journeys)
        out = os.path.join(d, "traj.json")
        rc = run_journeys.main([
            "--journeys", jf, "--shard", "0", "--shards", "1",
            "--izba-bin", stub, "--data-dir", d, "--out", out,
            "--fake-model", json.dumps(fake_script),
            "--step-cap", "25", "--action-timeout-s", "10",
            "--max-turns", "10", "--max-usd", "5",
        ])
        with open(out) as f:
            return rc, json.load(f)

    def test_model_error_reply_emits_flipping_infra_candidate(self):
        with tempfile.TemporaryDirectory() as d:
            rc, bundle = self._run(d, [{"error": "openrouter request failed"}])
            cands = bundle["results"][0]["candidates"]
            infra = [c for c in cands if c["kind"] == "infra"]
            self.assertTrue(infra, cands)
            self.assertIn("openrouter request failed", infra[0]["detail"])
            # single journey, degraded -> catastrophic exit
            self.assertEqual(rc, 3)

    def test_infra_journey_not_positive_in_collector(self):
        collector = _load_collector()
        if collector is None:
            self.skipTest("collector script not present")
        with tempfile.TemporaryDirectory() as d:
            _, bundle = self._run(d, [{"error": "dead key"}])
            bdir = os.path.join(d, "bundles")
            os.makedirs(bdir)
            with open(os.path.join(bdir, "traj-0.json"), "w") as f:
                json.dump(bundle, f)
            data = collector.collect(bdir)
            self.assertEqual(data["totals"]["positive_journeys"], 0)

    def test_catastrophic_exit_only_above_half(self):
        # 1 of 3 journeys degraded (error on first journey's first turn; the
        # FakeModel script then supplies clean done-runs for the other two).
        with tempfile.TemporaryDirectory() as d:
            script = [{"error": "blip"},               # j0: degraded
                      {"command": "izba ls"}, {"done": True},   # j1: fine
                      {"command": "izba ls"}, {"done": True}]   # j2: fine
            rc, bundle = self._run(d, script, n_journeys=3)
            self.assertEqual(rc, 0)  # 1/3 <= 0.5 -> report-only

    def test_model_exception_emits_infra_candidate(self):
        class ExplodingModel:
            last_cost_usd = 0.0
            def next_command(self, *a):
                raise RuntimeError("kaboom")
        with tempfile.TemporaryDirectory() as d:
            stub = _write_stub_izba(d)
            journey = {"journey_id": "boom", "rationale": "r",
                       "source": {"kind": "spec", "ref": "x"},
                       "steps": [{"intent": "do", "expect": "works"}]}
            budget = {"usd": 0.0}
            res = run_journeys.run_journey(
                ExplodingModel(), journey, stub, d,
                max_turns=5, step_cap=5, action_timeout_s=5,
                latency_budget_ms=1000, budget=budget, max_usd=5)
            self.assertTrue(any(c["kind"] == "infra" for c in res["candidates"]))
```

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m pytest hack/dogfood/test_runner.py::InfraCandidateTests -q`
Expected: FAIL (no infra candidates emitted; rc is 0 everywhere).

- [ ] **Step 3: Implement in `run_journeys.py`**

(a) Add the constant near `DEFAULT_LATENCY_BUDGET_MS` (line 52):

```python
# Catastrophic-infra threshold: if MORE than this fraction of attempted
# journeys are degraded (zero actions, or >=1 `infra` candidate), the run
# was not a measurement — exit 3 so the CI job fails per the "only infra
# failures fail a job" contract. At or below the threshold stays report-only
# (a transient model blip must not kill a 40-minute shard).
CATASTROPHIC_DEGRADED_FRACTION = 0.5
EXIT_CATASTROPHIC_INFRA = 3


def _infra_candidate(journey_id: str, detail: str) -> Dict[str, Any]:
    """A flipping `infra` candidate: the harness/model plumbing failed, so the
    journey verified nothing (and must not tally positive)."""
    return {
        "kind": "infra",
        "detail": detail,
        "violated_expectation": "model/API must produce a next command",
        "source": "harness: model transport",
        "trajectory_ref": {"journey_id": journey_id, "action_index": -1},
    }
```

(b) Rework `_next_command` (line 243) to emit the candidate — new signature with `candidates`:

```python
def _next_command(model, journey, step, actions, budget, journey_id, candidates):
    """One model turn -> a command string, or None to end the step.

    A model-layer failure ({"error": ...} reply, or an exception) is an INFRA
    finding, not a completion: it appends a flipping `infra` candidate so the
    journey cannot tally positive on the back of a broken model."""
    try:
        reply = model.next_command(journey, step, actions)
        budget["usd"] += float(getattr(model, "last_cost_usd", 0.0) or 0.0)
    except Exception as e:  # report-only, but never silently green
        log(f"{journey_id}: model error: {e!r}; ending step")
        candidates.append(_infra_candidate(journey_id, f"model raised: {e!r}"))
        return None
    if isinstance(reply, dict) and reply.get("error"):
        log(f"{journey_id}: model infra error: {reply['error']}; ending step")
        candidates.append(_infra_candidate(journey_id, str(reply["error"])))
        return None
    if not isinstance(reply, dict) or reply.get("done"):
        return None
    command = reply.get("command")
    if not isinstance(command, str) or not command.strip():
        return None
    return command
```

Update the call site in `_run_step` (line 290): `command = _next_command(model, journey, step, actions, budget, journey_id, candidates)`.

(c) Degraded accounting in `main()` (lines 519-549). After the loop, before writing the bundle:

```python
    degraded = sum(
        1 for r in results
        if not r.get("actions")
        or any(c.get("kind") == "infra" for c in r.get("candidates", []))
    )
    catastrophic = bool(results) and degraded / len(results) > CATASTROPHIC_DEGRADED_FRACTION

    bundle = {"shard": args.shard, "feature": feature, "results": results}
    with open(args.out, "w") as f:
        json.dump(bundle, f, indent=2)
    log(f"wrote {args.out}: {len(results)} journeys ({degraded} degraded), "
        f"est. cost ${budget['usd']:.4f}")
    if catastrophic:
        log(f"CATASTROPHIC: {degraded}/{len(results)} journeys degraded "
            f"(> {CATASTROPHIC_DEGRADED_FRACTION:.0%}) — the run measured "
            f"nothing; failing the job (exit {EXIT_CATASTROPHIC_INFRA})")
        return EXIT_CATASTROPHIC_INFRA
    return 0
```

(d) Change the `--model` default (line 467): `default="google/gemini-2.5-flash"` and update its help to note deepseek-chat proved too weak (mirror dogfood.yml:29-31's comment).

(e) Update the module docstring (lines 10-14): exit code is 0 for findings, non-zero for unrecoverable startup errors, and **3** when >50% of journeys were infra-degraded.

- [ ] **Step 4: Run the full suite**

Run: `python3 -m pytest hack/dogfood/ -q`
Expected: ALL PASS. Watch for existing tests that assert `rc == 0` on runs whose journeys produce zero actions (e.g. an exhausted FakeModel) — those now exit 3. **If any fail, that's the new honest behavior:** update those tests to either supply a script producing ≥1 action or assert `rc == 3`. Check `test_runner.py` tests around caps (they all produce actions, so they should pass) and `test_oracles.py` (doesn't call `main()`).

- [ ] **Step 5: Commit**

```bash
git add hack/dogfood/run_journeys.py hack/dogfood/test_runner.py
git commit -m "feat(dogfood): flipping infra candidates + catastrophic exit 3 on degraded runs

Model/API failures now emit a flipping \`infra\` candidate (journey can't
tally positive), and a run with >50% degraded journeys (zero actions or
infra) exits 3 so the CI shard fails honestly — a dead OPENROUTER key no
longer produces an all-green run. Runner --model default aligned to CI's
google/gemini-2.5-flash (deepseek-chat is admitted-broken).

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: `unreached_decisive` candidate (#126)

**Files:**
- Modify: `hack/dogfood/run_journeys.py` (in `run_journey`, lines 373-424)
- Test: `hack/dogfood/test_runner.py` (append)

**Interfaces:**
- Produces: candidate `{"kind": "unreached_decisive", "detail": "decisive step <i> (<intent…>) produced no actions", "violated_expectation": <step expect or fallback>, "source": <journey source ref>, "trajectory_ref": {"journey_id": jid, "action_index": -1}}`. Emitted for every decisive step index that ran zero actions.

- [ ] **Step 1: Write the failing tests** (append to `test_runner.py`)

```python
class UnreachedDecisiveTests(unittest.TestCase):
    def _journey(self):
        return {
            "journey_id": "deep", "rationale": "r",
            "source": {"kind": "spec", "ref": "spec §9"},
            "steps": [
                {"intent": "setup", "expect": "ok"},
                {"intent": "the real assertion", "expect": "guard refuses",
                 "core": True},
            ],
        }

    def test_budget_burned_in_setup_flags_unreached_core(self):
        # Model does setup actions then goes silent (done) without ever
        # reaching step 2 — max-turns trips inside step 1.
        with tempfile.TemporaryDirectory() as d:
            stub = _write_stub_izba(d)
            jf = _journeys_file(d, [self._journey()])
            out = os.path.join(d, "traj.json")
            script = [{"command": f"izba ls-{i}"} for i in range(10)]
            run_journeys.main([
                "--journeys", jf, "--shard", "0", "--shards", "1",
                "--izba-bin", stub, "--data-dir", d, "--out", out,
                "--fake-model", json.dumps(script),
                "--step-cap", "25", "--action-timeout-s", "10",
                "--max-turns", "3", "--max-usd", "5",
            ])
            with open(out) as f:
                res = json.load(f)["results"][0]
            unreached = [c for c in res["candidates"]
                         if c["kind"] == "unreached_decisive"]
            self.assertEqual(len(unreached), 1, res["candidates"])
            self.assertIn("the real assertion", unreached[0]["detail"])

    def test_unreached_journey_not_positive_in_collector(self):
        collector = _load_collector()
        if collector is None:
            self.skipTest("collector script not present")
        with tempfile.TemporaryDirectory() as d:
            stub = _write_stub_izba(d)
            jf = _journeys_file(d, [self._journey()])
            out = os.path.join(d, "bundles", "traj-0.json")
            os.makedirs(os.path.dirname(out))
            run_journeys.main([
                "--journeys", jf, "--shard", "0", "--shards", "1",
                "--izba-bin", stub, "--data-dir", d, "--out", out,
                "--fake-model", json.dumps(
                    [{"command": "izba setup-thing"}] * 5),
                "--step-cap", "25", "--action-timeout-s", "10",
                "--max-turns", "2", "--max-usd", "5",
            ])
            data = collector.collect(os.path.dirname(out))
            self.assertEqual(data["totals"]["positive_journeys"], 0)

    def test_reached_decisive_step_emits_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            stub = _write_stub_izba(d)
            jf = _journeys_file(d, [self._journey()])
            out = os.path.join(d, "traj.json")
            script = [{"command": "izba ls"}, {"done": True},        # step 1
                      {"command": "izba bogus-subcommand"}, {"done": True}]  # step 2 (nonzero = refusal ok)
            run_journeys.main([
                "--journeys", jf, "--shard", "0", "--shards", "1",
                "--izba-bin", stub, "--data-dir", d, "--out", out,
                "--fake-model", json.dumps(script),
                "--step-cap", "25", "--action-timeout-s", "10",
                "--max-turns", "10", "--max-usd", "5",
            ])
            with open(out) as f:
                res = json.load(f)["results"][0]
            self.assertFalse([c for c in res["candidates"]
                              if c["kind"] == "unreached_decisive"],
                             res["candidates"])
```

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m pytest hack/dogfood/test_runner.py::UnreachedDecisiveTests -q`
Expected: first two FAIL (`unreached_decisive` never emitted); third passes vacuously.

- [ ] **Step 3: Implement in `run_journeys.py`**

In `run_journey`, track per-step production and emit after the loop. Replace the steps loop (lines 406-415) with:

```python
    decisive_idx = _decisive_step_indices(steps)
    step_actions: Dict[int, int] = {}  # step index -> actions it produced
    for i, step in enumerate(steps):
        before = len(actions)
        stop = _run_step(
            model, journey, step, izba_bin, data_dir, workdir,
            action_timeout_s=action_timeout_s, latency_budget_ms=latency_budget_ms,
            budget=budget, max_usd=max_usd, max_turns=max_turns, step_cap=step_cap,
            journey_id=journey_id, actions=actions, candidates=candidates, ctx=ctx,
            decisive=(i in decisive_idx), cwd_file=cwd_file)
        step_actions[i] = len(actions) - before
        if stop:
            break
    # #126: a decisive step the Actor never reached (or reached with zero
    # actions) verified NOTHING — emit a flipping candidate so the journey
    # can't tally positive on budget exhaustion before its core assertion.
    source = journey.get("source", {}).get("ref", "journey step")
    for i in sorted(decisive_idx):
        if step_actions.get(i, 0) == 0:
            s = steps[i]
            candidates.append({
                "kind": "unreached_decisive",
                "detail": (f"decisive step {i} ({s.get('intent', '')[:80]!r}) "
                           f"produced no actions — its assertion was never "
                           f"exercised"),
                "violated_expectation": s.get("expect", "")
                                        or "decisive step must be exercised",
                "source": source,
                "trajectory_ref": {"journey_id": journey_id, "action_index": -1},
            })
```

- [ ] **Step 4: Run the full suite**

Run: `python3 -m pytest hack/dogfood/ -q`
Expected: ALL PASS. Note: `test_step_cap_halts_runaway_loop` and friends have single-step journeys that DO produce actions — unaffected. A pre-existing test with `steps: []` gets the synthetic step (line 404) which then produces actions or not; if a legacy test now sees an unexpected `unreached_decisive`, that test's journey genuinely never reached its assertion — extend the test's expectations, don't weaken the oracle.

- [ ] **Step 5: Commit**

```bash
git add hack/dogfood/run_journeys.py hack/dogfood/test_runner.py
git commit -m "feat(dogfood): flag decisive steps the Actor never reached (closes #126)

A journey that burned its budget before its core step produced zero graded
actions -> zero candidates -> tallied POSITIVE. Now every decisive step
with zero actions emits a flipping unreached_decisive candidate.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: grade reconcile `violations`; make failed snapshots visible

**Files:**
- Modify: `hack/dogfood/oracles.py` (`_snapshot_reconcile` line 193, `reconcile_seq_oracle` line 475), `hack/dogfood/run_journeys.py` (`_collect_candidates` line 180, `run_journey`)
- Test: `hack/dogfood/test_oracles.py` + `hack/dogfood/test_runner.py`

**Interfaces:**
- Produces: `_snapshot_reconcile` error shape `{"error": "<reason>", "violations": [], "sandboxes": []}`. Candidate `{"kind": "reconcile_violation", "detail": "...", …}` (one per action that has non-empty violations, carrying up to the first 3 violation objects serialized in detail). Journey-level `infra` candidate `"detail": "reconciler unusable: every snapshot errored"` when all of a journey's actions have `reconcile.error`.

- [ ] **Step 1: Write the failing tests**

Append to `test_oracles.py`:

```python
class ReconcileVisibilityTests(unittest.TestCase):
    def test_snapshot_failure_has_error_key(self):
        import oracles
        # A binary that is not there -> OSError path.
        snap = oracles._snapshot_reconcile(
            "/nonexistent/izba", "/tmp", 5,
            oracles._shell_env("/nonexistent/izba", "/tmp"))
        self.assertIn("error", snap)
        self.assertEqual(snap["violations"], [])

    def test_seq_oracle_skips_error_snapshots(self):
        import oracles
        prev = {"error": "boom", "violations": [], "sandboxes": []}
        cur = {"violations": [], "sandboxes": [
            {"name": "s", "status_disk": "running",
             "vmm": {"pid": 1, "starttime": 2}}]}
        self.assertEqual(oracles.reconcile_seq_oracle(prev, cur), [])
        self.assertEqual(oracles.reconcile_seq_oracle(cur, prev), [])
```

Append to `test_runner.py`:

```python
class ReconcileViolationTests(unittest.TestCase):
    def _stub_with_violations(self, d):
        stub = os.path.join(d, "izba")
        with open(stub, "w") as f:
            f.write(
                "#!/bin/sh\n"
                'if [ "$1" = "__reconcile" ]; then\n'
                '  echo \'{"violations":[{"kind":"orphan-relay","name":"web"}],"sandboxes":[]}\'\n'
                "  exit 0\nfi\n"
                "echo ok\nexit 0\n")
        os.chmod(stub, 0o755)
        return stub

    def test_nonempty_violations_emit_flipping_candidate(self):
        with tempfile.TemporaryDirectory() as d:
            stub = self._stub_with_violations(d)
            jf = _journeys_file(d, [{
                "journey_id": "viol", "rationale": "r",
                "source": {"kind": "spec", "ref": "x"},
                "steps": [{"intent": "do", "expect": "ok"}]}])
            out = os.path.join(d, "traj.json")
            run_journeys.main([
                "--journeys", jf, "--shard", "0", "--shards", "1",
                "--izba-bin", stub, "--data-dir", d, "--out", out,
                "--fake-model", json.dumps([{"command": "izba ls"}, {"done": True}]),
                "--step-cap", "25", "--action-timeout-s", "10",
                "--max-turns", "10", "--max-usd", "5"])
            with open(out) as f:
                res = json.load(f)["results"][0]
            rv = [c for c in res["candidates"] if c["kind"] == "reconcile_violation"]
            self.assertTrue(rv, res["candidates"])
            self.assertIn("orphan-relay", rv[0]["detail"])

    def test_all_snapshots_failed_emits_infra(self):
        with tempfile.TemporaryDirectory() as d:
            stub = os.path.join(d, "izba")
            with open(stub, "w") as f:
                f.write("#!/bin/sh\n"
                        'if [ "$1" = "__reconcile" ]; then exit 7; fi\n'
                        "echo ok\nexit 0\n")
            os.chmod(stub, 0o755)
            jf = _journeys_file(d, [{
                "journey_id": "deadrec", "rationale": "r",
                "source": {"kind": "spec", "ref": "x"},
                "steps": [{"intent": "do", "expect": "ok"}]}])
            out = os.path.join(d, "traj.json")
            run_journeys.main([
                "--journeys", jf, "--shard", "0", "--shards", "1",
                "--izba-bin", stub, "--data-dir", d, "--out", out,
                "--fake-model", json.dumps([{"command": "izba ls"}, {"done": True}]),
                "--step-cap", "25", "--action-timeout-s", "10",
                "--max-turns", "10", "--max-usd", "5"])
            with open(out) as f:
                res = json.load(f)["results"][0]
            infra = [c for c in res["candidates"] if c["kind"] == "infra"]
            self.assertTrue(any("reconciler unusable" in c["detail"] for c in infra),
                            res["candidates"])
```

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m pytest hack/dogfood/test_oracles.py::ReconcileVisibilityTests hack/dogfood/test_runner.py::ReconcileViolationTests -q`
Expected: FAIL (`error` key absent; no `reconcile_violation`/`infra` candidates).

- [ ] **Step 3: Implement**

`oracles.py::_snapshot_reconcile` (line 193):

```python
def _snapshot_reconcile(
    izba_bin: str, data_dir: str, timeout_s: float, env: Dict[str, str]
) -> Dict[str, Any]:
    """Best-effort ``izba __reconcile --json``.

    Report-only, but honest: a FAILED snapshot returns an ``error`` key so a
    broken reconciler is distinguishable from a clean one (previously both
    yielded the same empty shape, hiding a dead oracle)."""
    import json

    err = "unknown"
    try:
        proc = subprocess.run(
            [izba_bin, "__reconcile", "--json"],
            capture_output=True,
            text=True,
            timeout=timeout_s,
            env=env,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return json.loads(proc.stdout)
        err = f"exit {proc.returncode}: {(proc.stderr or '')[-200:]}"
    except (subprocess.TimeoutExpired, OSError, ValueError) as e:
        err = repr(e)
    return {"error": err, "violations": [], "sandboxes": []}
```

`oracles.py::reconcile_seq_oracle` — insert at the top of the function body (line 490):

```python
    # An errored snapshot carries no state; comparing against it would fabricate
    # transitions. Skip (the runner separately flags an all-errored journey).
    if (prev_snapshot or {}).get("error") or (cur_snapshot or {}).get("error"):
        return []
```

`run_journeys.py::_collect_candidates` — after the existing `found` block (line 194), add:

```python
    violations = (action.reconcile or {}).get("violations") or []
    if violations:
        import json as _json
        found = list(found)
        preview = _json.dumps(violations[:3])[:400]
        found.append(Candidate(
            kind="reconcile_violation",
            detail=(f"izba __reconcile reported {len(violations)} violation(s) "
                    f"after {command!r}: {preview}"),
            violated_expectation="reconciler must report no violations "
                                 "(declared state == reality)",
            source="contract: disk-state invariant (__reconcile)",
        ))
```

(Note `Candidate` needs importing in run_journeys.py: extend the existing `from oracles import (...)` block with `Candidate`.)

`run_journeys.py::run_journey` — after the unreached_decisive block from Task 3, add:

```python
    # A journey whose EVERY snapshot errored had no reconcile oracle at all.
    if actions and all((a.get("reconcile") or {}).get("error") for a in actions):
        candidates.append(_infra_candidate(
            journey_id, "reconciler unusable: every snapshot errored"))
```

- [ ] **Step 4: Run the full suite**

Run: `python3 -m pytest hack/dogfood/ -q`
Expected: ALL PASS. (The GUI runner's own `_reconcile_snapshot` in `run_gui_journeys.py:52-68` is separate and untouched here.)

- [ ] **Step 5: Commit**

```bash
git add hack/dogfood/oracles.py hack/dogfood/run_journeys.py hack/dogfood/test_oracles.py hack/dogfood/test_runner.py
git commit -m "feat(dogfood): grade reconcile violations; make failed snapshots visible

The __reconcile violations array was captured into every action and read
by NOBODY (spec §0.3); a failed snapshot was indistinguishable from a
clean one. Non-empty violations now emit a flipping reconcile_violation
candidate; error snapshots carry an error key, are skipped by the seq
oracle, and an all-errored journey emits an infra candidate.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 5: `expect_cmd_re` — grade the intent-bearing action

**Files:**
- Modify: `hack/dogfood/run_journeys.py` (`_grade_step_functional`, line 215), `hack/dogfood/schema/journeys.schema.json` (step definition, line 85-109)
- Test: `hack/dogfood/test_runner.py`

**Interfaces:**
- Consumes: journey step field `expect_cmd_re` (optional regex string).
- Produces: functional candidates gain `"graded_cmd": "<command>"`; grading target = last action in the step whose command matches `expect_cmd_re`, falling back to the step's final action.

- [ ] **Step 1: Write the failing tests** (append to `test_runner.py`)

```python
class ExpectCmdReTests(unittest.TestCase):
    def _run(self, d, step, script):
        stub = _write_stub_izba(d)
        jf = _journeys_file(d, [{
            "journey_id": "anchor", "rationale": "r",
            "source": {"kind": "spec", "ref": "x"},
            "steps": [step]}])
        out = os.path.join(d, "traj.json")
        run_journeys.main([
            "--journeys", jf, "--shard", "0", "--shards", "1",
            "--izba-bin", stub, "--data-dir", d, "--out", out,
            "--fake-model", json.dumps(script),
            "--step-cap", "25", "--action-timeout-s", "10",
            "--max-turns", "10", "--max-usd", "5"])
        with open(out) as f:
            return json.load(f)["results"][0]

    def test_grades_matching_action_not_trailing_verify(self):
        # The refusal (bogus-subcommand, exit 2) is followed by a passing
        # `izba ls` verify. expect_exit=nonzero must be graded against the
        # promote-like command, so NO candidate fires.
        step = {"intent": "try the guarded op", "expect": "must be refused",
                "expect_exit": "nonzero", "core": True,
                "expect_cmd_re": r"bogus-subcommand"}
        with tempfile.TemporaryDirectory() as d:
            res = self._run(d, step, [
                {"command": "izba bogus-subcommand"},
                {"command": "izba ls"},
                {"done": True}])
            func = [c for c in res["candidates"] if c["kind"] == "functional"]
            self.assertEqual(func, [], func)

    def test_without_anchor_trailing_verify_false_fires(self):
        # Same trajectory WITHOUT expect_cmd_re: the final action (ls, exit 0)
        # is graded against nonzero -> false candidate. Locks in the motivation.
        step = {"intent": "try the guarded op", "expect": "must be refused",
                "expect_exit": "nonzero", "core": True}
        with tempfile.TemporaryDirectory() as d:
            res = self._run(d, step, [
                {"command": "izba bogus-subcommand"},
                {"command": "izba ls"},
                {"done": True}])
            func = [c for c in res["candidates"] if c["kind"] == "functional"]
            self.assertEqual(len(func), 1)
            self.assertEqual(func[0].get("graded_cmd"), "izba ls")

    def test_bad_regex_falls_back_to_last_action(self):
        step = {"intent": "x", "expect": "works", "core": True,
                "expect_cmd_re": "["}  # invalid regex
        with tempfile.TemporaryDirectory() as d:
            res = self._run(d, step, [{"command": "izba ls"}, {"done": True}])
            # ls exits 0 and expect describes success -> no candidate; and no crash.
            self.assertEqual([c for c in res["candidates"]
                              if c["kind"] == "functional"], [])
```

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m pytest hack/dogfood/test_runner.py::ExpectCmdReTests -q`
Expected: `test_grades_matching_action_not_trailing_verify` FAILS (candidate fires on `izba ls`); `test_without_anchor…` fails on the missing `graded_cmd` key.

- [ ] **Step 3: Implement**

Replace `_grade_step_functional` (run_journeys.py:215-240):

```python
def _grade_step_functional(step, produced, journey, journey_id, decisive,
                           action_index) -> List[Dict[str, Any]]:
    """Grade the functional assertion ONCE per step, on its intent-bearing action.

    Default target is the step's FINAL action. When the step declares
    ``expect_cmd_re`` (a regex), the target is the LAST action whose command
    matches — so a trailing verify (`izba ls`) after a correct refusal no
    longer false-fires, and a refusal followed by unrelated commands is still
    the thing graded. Invalid regexes log + fall back to the final action.
    Every candidate records ``graded_cmd`` so the skeptic sees WHAT was graded."""
    if not produced:
        return []
    target = produced[-1]
    target_index = action_index
    pattern = step.get("expect_cmd_re")
    if isinstance(pattern, str) and pattern:
        try:
            rx = re.compile(pattern)
            for off, a in enumerate(reversed(produced)):
                if rx.search(a.get("command", "")):
                    target = a
                    target_index = action_index - off
                    break
        except re.error as e:
            log(f"{journey_id}: invalid expect_cmd_re {pattern!r}: {e}; "
                f"grading the final action")
    ref = {"journey_id": journey_id, "action_index": target_index}
    source = journey.get("source", {}).get("ref", "journey step")
    found = functional_oracle(
        target.get("command", ""), target.get("exit_code", 0),
        step.get("expect", ""), source, ref,
        expect_exit=step.get("expect_exit"))
    out = []
    for c in found:
        cd = c.to_dict()
        cd["trajectory_ref"] = ref
        cd["decisive"] = bool(decisive)
        cd["graded_cmd"] = target.get("command", "")
        out.append(cd)
    return out
```

In `journeys.schema.json`, add to the `step` properties (after `expect_exit`, line 108):

```json
        "expect_cmd_re": {
          "type": "string",
          "description": "Optional regex anchoring WHICH of the step's actions the functional/expect_exit verdict is graded against: the LAST action whose command matches. Without it the step's final action is graded — which false-fires when the Actor runs a trailing verify (e.g. `izba ls`) after the intent-bearing command. Compiler rule: set it on refusal/expect_exit steps to the distinctive token of the command under test (e.g. 'promote'); never anchor to an exact full command line (that would leak a prescription to the swarm's benefit — the regex lives here, invisible to the Actor)."
        }
```

- [ ] **Step 4: Run the full suite**

Run: `python3 -m pytest hack/dogfood/ -q`
Expected: ALL PASS (the existing `DecisiveGradingTests` grade final actions of steps without `expect_cmd_re` — behavior unchanged).

- [ ] **Step 5: Commit**

```bash
git add hack/dogfood/run_journeys.py hack/dogfood/schema/journeys.schema.json hack/dogfood/test_runner.py
git commit -m "feat(dogfood): expect_cmd_re anchors grading to the intent-bearing action

The functional/expect_exit verdict was graded against the step's LAST
action — a trailing 'izba ls' verify after a correct refusal false-fired,
and any failing command satisfied 'nonzero'. Steps can now anchor the
graded action by regex; candidates record graded_cmd for the skeptic.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 6: guest console oracle + per-journey teardown

**Files:**
- Modify: `hack/dogfood/oracles.py` (`capture_state_evidence` line 232, new `guest_console_oracle`, new `teardown_journey`), `hack/dogfood/run_journeys.py` (`run_journey` end)
- Test: `hack/dogfood/test_oracles.py`

**Interfaces:**
- Produces: `capture_state_evidence` result gains `per_sandbox[name]["console_tail"]` (last 8192 bytes of `<data_dir>/sandboxes/<name>/logs/console.log`, `""` if absent). New `guest_console_oracle(state_evidence, ref) -> List[Candidate]` (kind `guest_console`, flipping). New `teardown_journey(izba_bin, data_dir, timeout_s, names)` — best-effort `izba rm <name> --force` per name + `izba daemon stop`; returns nothing, never raises.

- [ ] **Step 1: Write the failing tests** (append to `test_oracles.py`)

```python
class GuestConsoleTests(unittest.TestCase):
    def _stub(self, d, names=("web",)):
        import json as _json
        stub = os.path.join(d, "izba")
        sandboxes = _json.dumps([{"name": n} for n in names])
        with open(stub, "w") as f:
            f.write(
                "#!/bin/sh\n"
                'if [ "$1" = "__reconcile" ]; then\n'
                f"  echo '{{\"violations\":[],\"sandboxes\":{sandboxes}}}'\n"
                "  exit 0\nfi\n"
                "echo ok\nexit 0\n")
        os.chmod(stub, 0o755)
        return stub

    def test_console_tail_captured_and_panic_flagged(self):
        import oracles
        with tempfile.TemporaryDirectory() as d:
            stub = self._stub(d)
            logdir = os.path.join(d, "sandboxes", "web", "logs")
            os.makedirs(logdir)
            with open(os.path.join(logdir, "console.log"), "w") as f:
                f.write("boot ok\nthread 'main' panicked at init.rs:42\n")
            ev = oracles.capture_state_evidence(stub, d, 5)
            self.assertIn("panicked", ev["per_sandbox"]["web"]["console_tail"])
            cands = oracles.guest_console_oracle(
                ev, {"journey_id": "j", "action_index": -1})
            self.assertEqual(len(cands), 1)
            self.assertEqual(cands[0].kind, "guest_console")

    def test_clean_console_emits_nothing(self):
        import oracles
        with tempfile.TemporaryDirectory() as d:
            stub = self._stub(d)
            logdir = os.path.join(d, "sandboxes", "web", "logs")
            os.makedirs(logdir)
            with open(os.path.join(logdir, "console.log"), "w") as f:
                f.write("boot ok\ninit: reached target\n")
            ev = oracles.capture_state_evidence(stub, d, 5)
            self.assertEqual(oracles.guest_console_oracle(
                ev, {"journey_id": "j", "action_index": -1}), [])

    def test_missing_console_is_empty_not_error(self):
        import oracles
        with tempfile.TemporaryDirectory() as d:
            stub = self._stub(d)
            ev = oracles.capture_state_evidence(stub, d, 5)
            self.assertEqual(ev["per_sandbox"]["web"]["console_tail"], "")


class TeardownTests(unittest.TestCase):
    def test_teardown_invokes_rm_force_and_daemon_stop(self):
        import oracles
        with tempfile.TemporaryDirectory() as d:
            calls = os.path.join(d, "calls.log")
            stub = os.path.join(d, "izba")
            with open(stub, "w") as f:
                f.write(f'#!/bin/sh\necho "$@" >> {calls}\nexit 0\n')
            os.chmod(stub, 0o755)
            oracles.teardown_journey(stub, d, 5, ["web", "db"])
            with open(calls) as f:
                lines = f.read().splitlines()
            self.assertIn("rm web --force", lines)
            self.assertIn("rm db --force", lines)
            self.assertIn("daemon stop", lines)

    def test_teardown_never_raises(self):
        import oracles
        oracles.teardown_journey("/nonexistent/izba", "/tmp", 1, ["x"])
```

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m pytest hack/dogfood/test_oracles.py::GuestConsoleTests hack/dogfood/test_oracles.py::TeardownTests -q`
Expected: FAIL (`console_tail` key missing; `guest_console_oracle`/`teardown_journey` don't exist).

- [ ] **Step 3: Implement in `oracles.py`**

Add near `TAIL_BYTES` (line 33): `CONSOLE_TAIL_BYTES = 8192`.

In `capture_state_evidence` (line 248-255), extend the per-sandbox block:

```python
    for name in names:
        console_tail = ""
        try:
            console_path = os.path.join(data_dir, "sandboxes", name,
                                        "logs", "console.log")
            with open(console_path, "rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(max(0, size - CONSOLE_TAIL_BYTES))
                console_tail = f.read().decode("utf-8", errors="replace")
        except OSError:
            pass  # absent console.log is the normal never-booted state
        per_sandbox[name] = {
            "policy_show": _izba_capture(izba_bin, ["policy", "show", name],
                                         timeout_s, run_env),
            "netlog": _izba_capture(izba_bin, ["netlog", name, "--summary"],
                                    timeout_s, run_env),
            "console_tail": console_tail,
        }
```

Add after `implicit_oracle` (line 322):

```python
def guest_console_oracle(state_evidence: Dict[str, Any],
                         ref: Dict[str, Any]) -> List[Candidate]:
    """Scan each sandbox's guest serial-console tail for crash markers.

    The guest console is the documented always-captured boot truth
    (logs/console.log), yet no oracle read it — a guest-side panic that never
    surfaced in CLI stderr was invisible. Same marker regex as the implicit
    oracle; one candidate per affected sandbox."""
    out: List[Candidate] = []
    for name, ev in (state_evidence.get("per_sandbox") or {}).items():
        tail = ev.get("console_tail") or ""
        m = _IMPLICIT_RE.search(tail)
        if m:
            out.append(Candidate(
                kind="guest_console",
                detail=(f"crash marker {m.group(0)!r} in guest console of "
                        f"sandbox {name!r}"),
                violated_expectation="guest must not panic/abort (console.log)",
                source="contract: clean guest boot/run, no panics",
                trajectory_ref=dict(ref),
            ))
    return out


def teardown_journey(izba_bin: str, data_dir: str, timeout_s: float,
                     names: List[str]) -> None:
    """Best-effort per-journey cleanup: remove this journey's sandboxes and stop
    its (data-dir-scoped) daemon so leftover VMs don't skew later journeys'
    latency/boot behavior on the shard. Hygiene, not an oracle: failures are
    logged to stderr and swallowed — teardown must never fail a journey."""
    run_env = _shell_env(izba_bin, data_dir)
    for argv in [["rm", n, "--force"] for n in names] + [["daemon", "stop"]]:
        try:
            subprocess.run([izba_bin, *argv], capture_output=True, text=True,
                           timeout=timeout_s, env=run_env)
        except (subprocess.TimeoutExpired, OSError) as e:
            print(f"[dogfood] teardown {argv}: {e!r}", file=__import__('sys').stderr)
```

(Use a plain `import sys` at module top instead of the inline import if `sys` isn't already imported — check the imports block at oracles.py:21-29 and add `import sys` there.)

- [ ] **Step 4: Wire into `run_journeys.py::run_journey`**

Extend the oracles import (line 40-47) with `guest_console_oracle, teardown_journey`. After the `state_evidence` capture block (line 418-422), add:

```python
    for cd in guest_console_oracle(
            state_evidence, {"journey_id": journey_id, "action_index": -1}):
        d = cd.to_dict()
        candidates.append(d)
    # Hygiene: tear down this journey's sandboxes + daemon so shard N+5's
    # latency isn't skewed by N's leftover VMs. Best-effort by contract.
    try:
        teardown_journey(izba_bin, data_dir, action_timeout_s,
                         state_evidence.get("sandboxes") or [])
    except Exception as e:  # defensive: teardown_journey shouldn't raise
        log(f"{journey_id}: teardown error: {e!r}")
```

- [ ] **Step 5: Run the full suite**

Run: `python3 -m pytest hack/dogfood/ -q`
Expected: ALL PASS. **Watch:** existing `test_oracles.py` state-evidence tests use stub izba binaries whose `rm`/`daemon` verbs echo "ok" — teardown is harmless there. `test_runner.py` stubs likewise.

- [ ] **Step 6: Commit**

```bash
git add hack/dogfood/oracles.py hack/dogfood/run_journeys.py hack/dogfood/test_oracles.py
git commit -m "feat(dogfood): guest-console crash oracle + per-journey teardown

Guest serial console (the documented boot-truth channel) was scanned by
no oracle — a guest panic invisible in CLI stderr went unflagged. Journey
end now tails logs/console.log per sandbox into state evidence and flags
crash markers (flipping guest_console kind), then best-effort removes the
journey's sandboxes and stops its daemon so leftover VMs stop skewing
later journeys on the shard.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 7: schema sync + write-time bundle validation + rubric-judge cleanup

**Files:**
- Modify: `hack/dogfood/schema/trajectory.schema.json`, `hack/dogfood/schema/journeys.schema.json` (step.expect description, line 96), `hack/dogfood/oracles.py` (lines ~237, ~339, ~392), `hack/dogfood/run_journeys.py` (line ~417 comment + `main`)
- Test: `hack/dogfood/test_runner.py`

**Interfaces:**
- Produces: `trajectory.schema.json` candidate.kind enum includes `infra`, `unreached_decisive`, `reconcile_violation`, `guest_console`; candidate gains optional `graded_cmd` (string); action.reconcile gains optional `error` (string); journey_result gains optional `invoke_log` (array; used by Task 9); state_evidence description mentions `console_tail`. `run_journeys.main` validates the bundle with `jsonschema` when importable (warning only).

- [ ] **Step 1: Write the failing test** (append to `test_runner.py`)

```python
class BundleSchemaTests(unittest.TestCase):
    def test_full_run_bundle_validates(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema not installed")
        with tempfile.TemporaryDirectory() as d:
            stub = _write_stub_izba(d)
            jf = _journeys_file(d, [{
                "journey_id": "ok", "rationale": "r",
                "source": {"kind": "spec", "ref": "x"},
                "steps": [{"intent": "list", "expect": "works", "core": True,
                           "expect_cmd_re": "ls"}]},
                {"journey_id": "err", "rationale": "r",
                 "source": {"kind": "spec", "ref": "x"},
                 "steps": [{"intent": "boom", "expect": "works"}]}])
            out = os.path.join(d, "traj.json")
            run_journeys.main([
                "--journeys", jf, "--shard", "0", "--shards", "1",
                "--izba-bin", stub, "--data-dir", d, "--out", out,
                "--fake-model", json.dumps([
                    {"command": "izba ls"}, {"done": True},   # journey ok
                    {"error": "transport down"}]),            # journey err
                "--step-cap", "25", "--action-timeout-s", "10",
                "--max-turns", "10", "--max-usd", "5"])
            schema_path = os.path.join(os.path.dirname(
                os.path.abspath(run_journeys.__file__)),
                "schema", "trajectory.schema.json")
            with open(schema_path) as f:
                schema = json.load(f)
            with open(out) as f:
                bundle = json.load(f)
            jsonschema.validate(bundle, schema)  # raises on mismatch
```

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m pytest hack/dogfood/test_runner.py::BundleSchemaTests -q`
Expected: FAIL — `jsonschema.ValidationError`: `'infra'` (and/or `graded_cmd`) not permitted by the current schema. (If `jsonschema` is missing locally: `pip install jsonschema` — CI's pytest venv installs it; check `.github/workflows/ci.yml`'s dogfood-tests step and add it there if absent.)

- [ ] **Step 3: Update the schemas**

`trajectory.schema.json`:
- candidate.kind enum (line 84) → `["functional", "latency", "implicit", "reconcile_seq", "infra", "unreached_decisive", "reconcile_violation", "guest_console", "console", "ui_daemon_diff", "silent_failure", "dom_expect"]`; extend the description: `infra` = harness/model transport failure (journey verified nothing), `unreached_decisive` = a decisive step produced no actions (#126), `reconcile_violation` = `izba __reconcile` reported violations, `guest_console` = crash marker in a guest's console.log.
- candidate properties: add `"graded_cmd": { "type": "string", "description": "Functional oracle only: the exact command whose exit code was graded (the expect_cmd_re-selected action, or the step's final action)." }`
- action.reconcile properties: add `"error": { "type": "string", "description": "Present iff the __reconcile snapshot itself failed (spawn/timeout/parse) — the snapshot carries no state and the seq oracle skipped it." }`
- journey_result properties: add `"invoke_log": { "type": "array", "items": { "type": "object" }, "description": "GUI only: the in-page bridge's invoke log (command, ok/error, duration) captured at journey end — the evidence behind silent_failure verdicts." }`
- state_evidence description (line 40): replace "the rubric judge grades outcomes against" with "the Phase-3 trajectory-skeptic grades outcomes against"; append: "per_sandbox entries also carry console_tail (last 8 KiB of the guest serial console)."

`journeys.schema.json` step.expect description (line 96): replace "(judged by the rubric judge against product state — NOT a literal exit-code assertion)" with "(judged by the Phase-3 trajectory-skeptic against product state — NOT a literal exit-code assertion)".

- [ ] **Step 4: Reword the remaining rubric-judge references + add write-time validation**

- `oracles.py:237` (capture_state_evidence docstring): "for the **Phase-3 trajectory-skeptic** to grade outcomes against (the τ-bench \"end-state\" oracle)."
- `oracles.py:339` (comment in `_EXPECT_FAILURE_RE` block): "…captured as state evidence, then graded by the **Phase-3 skeptic** — not here."
- `oracles.py:392` (functional_oracle docstring): "Egress/UX outcomes are judged from product state **by the Phase-3 skeptic**; this only catches…"
- `run_journeys.py:416-417` comment: "so the **Phase-3 skeptic** grades the outcome from ground truth, not guest exit codes."

In `run_journeys.py::main`, after writing the bundle (before the catastrophic check):

```python
    try:
        import jsonschema  # optional: report-only validation
        schema_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "schema", "trajectory.schema.json")
        with open(schema_path) as f:
            jsonschema.validate(bundle, json.load(f))
    except ImportError:
        pass
    except Exception as e:
        log(f"WARNING: bundle does not validate against trajectory.schema.json: {e}")
```

- [ ] **Step 5: Run the full suite, commit**

Run: `python3 -m pytest hack/dogfood/ -q` → ALL PASS.

```bash
git add hack/dogfood/schema/ hack/dogfood/oracles.py hack/dogfood/run_journeys.py hack/dogfood/test_runner.py
git commit -m "feat(dogfood): sync schemas with new candidate kinds; validate bundles at write time

Adds infra/unreached_decisive/reconcile_violation/guest_console to the
trajectory schema (+ graded_cmd, reconcile.error, invoke_log), validates
emitted bundles when jsonschema is importable (report-only warning), and
deletes the four references to the never-built 'rubric judge' — judgment
stays with the Phase-3 skeptic per the spec's placement model.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 8: collector — widened glob, honest buckets, modality tag

**Files:**
- Modify: `.claude/skills/llm-dogfooding/scripts/collect-trajectories.py`
- Test: `hack/dogfood/test_runner.py` (extend, via `_load_collector()`)

**Interfaces:**
- Produces: `load_bundles` matches `*traj-*.json` (so `gui-traj-0.json` is ingested). Each negative/soft/positive row gains `"modality": "gui"|"cli"` (from the bundle filename). `collect()` totals gain `"infra_journeys"` and `"unreached_journeys"`; new top-level `"unreached"` list (journey refs with ≥1 `unreached_decisive` candidate). `infra` is explicitly documented as flipping.

- [ ] **Step 1: Write the failing tests** (append to `test_runner.py`)

```python
class CollectorBucketsTests(unittest.TestCase):
    def _mk_bundle(self, d, fname, results):
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, fname), "w") as f:
            json.dump({"shard": 0, "feature": "t", "results": results}, f)

    def test_gui_bundles_are_collected_with_modality(self):
        collector = _load_collector()
        if collector is None:
            self.skipTest("collector script not present")
        with tempfile.TemporaryDirectory() as d:
            self._mk_bundle(d, "traj-0.json", [
                {"journey_id": "cli-j", "actions": [], "candidates": []}])
            self._mk_bundle(d, "gui-traj-0.json", [
                {"journey_id": "gui-j", "actions": [], "candidates": []}])
            data = collector.collect(d)
            self.assertEqual(data["totals"]["journeys"], 2)
            mods = {p["journey_id"]: p["modality"] for p in data["positives"]}
            # NOTE: zero-action journeys stop being positive once Task 3's
            # unreached candidates are in real bundles; these synthetic results
            # have no candidates, so they still land in positives here.
            self.assertEqual(mods, {"cli-j": "cli", "gui-j": "gui"})

    def test_infra_and_unreached_buckets(self):
        collector = _load_collector()
        if collector is None:
            self.skipTest("collector script not present")
        with tempfile.TemporaryDirectory() as d:
            self._mk_bundle(d, "traj-0.json", [
                {"journey_id": "dead", "actions": [], "candidates": [
                    {"kind": "infra", "detail": "x", "violated_expectation": "",
                     "source": "", "trajectory_ref": {"journey_id": "dead",
                                                      "action_index": -1}}]},
                {"journey_id": "shallow", "actions": [], "candidates": [
                    {"kind": "unreached_decisive", "detail": "y",
                     "violated_expectation": "", "source": "",
                     "trajectory_ref": {"journey_id": "shallow",
                                        "action_index": -1}}]}])
            data = collector.collect(d)
            self.assertEqual(data["totals"]["positive_journeys"], 0)
            self.assertEqual(data["totals"]["infra_journeys"], 1)
            self.assertEqual(data["totals"]["unreached_journeys"], 1)
            self.assertEqual([u["journey_id"] for u in data["unreached"]],
                             ["shallow"])
```

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m pytest hack/dogfood/test_runner.py::CollectorBucketsTests -q`
Expected: FAIL (gui bundle not globbed; buckets absent).

- [ ] **Step 3: Implement in `collect-trajectories.py`**

- Line 27 glob → `os.path.join(artifacts_dir, "**", "*traj-*.json")`, and line 30's message → `no *traj-*.json under …`.
- In `_is_flipping`'s docstring, add: "`infra` and `unreached_decisive` flip by design — an infra-degraded or never-reached journey must not tally positive (spec 2026-07-04); `reconcile_violation` and `guest_console` flip as product findings."
- In `collect()` (line 68), track the new buckets:

```python
def collect(artifacts_dir: str) -> dict:
    negatives, soft, positives, unreached = [], [], [], []
    by_kind = collections.Counter()
    n_journeys = 0
    infra_journeys = 0
    for path, bundle in load_bundles(artifacts_dir):
        shard = bundle.get("shard")
        modality = "gui" if os.path.basename(path).startswith("gui-") else "cli"
        for r in bundle.get("results", []):
            n_journeys += 1
            jid = r.get("journey_id")
            acts = r.get("actions", []) or []
            cands = r.get("candidates", []) or []
            ref = {"shard": shard, "journey_id": jid, "bundle": path,
                   "modality": modality}
            kinds = {c.get("kind") for c in cands}
            if "infra" in kinds:
                infra_journeys += 1
            if "unreached_decisive" in kinds:
                unreached.append(dict(ref))
            n_flipping = 0
            for c in cands:
                by_kind[c.get("kind", "?")] += 1
                row = {**ref, **{k: c.get(k) for k in
                       ("kind", "detail", "violated_expectation", "source")}}
                if c.get("graded_cmd") is not None:
                    row["graded_cmd"] = c.get("graded_cmd")
                if _is_flipping(c):
                    n_flipping += 1
                    negatives.append(row)
                else:
                    row["decisive"] = c.get("decisive")
                    soft.append(row)
            traj = [{"i": i, "cmd": a.get("command"), "exit": a.get("exit_code"),
                     "out": (a.get("stdout_tail") or "")[-160:],
                     "err": (a.get("stderr_tail") or "")[-160:]}
                    for i, a in enumerate(acts)]
            entry = {**ref, "n_actions": len(acts),
                     "exits": [a.get("exit_code") for a in acts],
                     "trajectory": traj}
            if n_flipping:
                entry["n_candidates"] = n_flipping
                entry["n_soft"] = len(cands) - n_flipping
            else:
                positives.append(entry)
    return {
        "artifacts_dir": artifacts_dir,
        "totals": {"journeys": n_journeys,
                   "candidates": sum(by_kind.values()),
                   "by_kind": dict(by_kind),
                   "flipping_candidates": len(negatives),
                   "soft_candidates": len(soft),
                   "positive_journeys": len(positives),
                   "infra_journeys": infra_journeys,
                   "unreached_journeys": len(unreached)},
        "negatives": negatives,
        "soft": soft,
        "positives": positives,
        "unreached": unreached,
    }
```

- In `main()`'s printout, extend the header line with `{t['infra_journeys']} infra / {t['unreached_journeys']} unreached-decisive`, and after the POSITIVE section add:

```python
    if data["unreached"]:
        print("\nUNREACHED-DECISIVE journeys (inconclusive — the core assertion "
              "was never exercised; tighten the journey or fix the blocking gap):")
        for u in data["unreached"]:
            print(f"  [{u['modality']}] {u['journey_id']}")
```

- [ ] **Step 4: Run the full suite, commit**

Run: `python3 -m pytest hack/dogfood/ -q` → ALL PASS.

```bash
git add .claude/skills/llm-dogfooding/scripts/collect-trajectories.py hack/dogfood/test_runner.py
git commit -m "feat(dogfood): collector ingests GUI bundles + honest infra/unreached buckets

gui-traj-*.json never matched the traj-*.json glob, so GUI runs never
reached Phase-3 collection. Rows now carry modality; totals expose
infra_journeys/unreached_journeys; unreached-decisive journeys print as
their own inconclusive section for the skeptic.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 9: GUI evidence — persist invoke log, per-action console deltas, infra on model error

**Files:**
- Modify: `hack/dogfood/gui/run_gui_journeys.py`
- Test: `hack/dogfood/gui/test_run_gui_journeys.py` (append; follow that file's existing FakeDriver/FakeModel patterns — read it first)

**Interfaces:**
- Consumes: `driver.read_console_errors()` (cumulative list), `driver.read_invoke_log()`, Task 1's `{"error"}` replies, Task 2's `_infra_candidate` shape (re-declare locally — do NOT import from run_journeys; keep the GUI runner's import surface as-is and define `_infra_candidate` in run_gui_journeys.py with identical fields).
- Produces: journey_result gains `"invoke_log": [...]`; each action's `console_errors` holds only the errors NEW since the previous action; model `{"error"}`/exception emits a flipping `infra` candidate.

- [ ] **Step 1: Read the existing GUI runner tests** (`hack/dogfood/gui/test_run_gui_journeys.py`) to learn the FakeDriver fixture, then write failing tests following its conventions:

```python
    # (inside the existing test class or a new one, reusing the file's fixtures)
    def test_invoke_log_persisted_in_result(self):
        # FakeDriver's read_invoke_log returns a canned list; assert the journey
        # result carries it verbatim under "invoke_log".
        ...

    def test_console_errors_are_per_action_deltas(self):
        # FakeDriver returns a GROWING cumulative list: ["e1"] after action 1,
        # ["e1", "e2"] after action 2. Assert action 1 records ["e1"] and
        # action 2 records ONLY ["e2"], and the console oracle fired once per
        # distinct error (2 candidates total, not 3).
        ...

    def test_model_error_reply_emits_infra_candidate(self):
        # FakeModel scripted with [{"error": "transport down"}]; assert the
        # journey's candidates include kind == "infra" and the journey has no
        # actions.
        ...
```

Write these as REAL tests against the file's actual fixtures (the fixtures already fake `driver.snapshot()`/`act()`; extend the fake driver with a mutable console list + invoke log if it lacks one). The three behaviors above are the contract; the fixture plumbing must match the existing style.

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m pytest hack/dogfood/gui/test_run_gui_journeys.py -q`
Expected: new tests FAIL (no invoke_log key; cumulative console re-counting; no infra candidate).

- [ ] **Step 3: Implement in `run_gui_journeys.py`**

(a) Add after `_cmd_hash` (line 107):

```python
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
```

(b) In `run_gui_journey`'s model-turn block (lines 147-153):

```python
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
```

(c) Console deltas: initialize `console_seen = 0` next to `turns = 0` (line 126); replace line 169:

```python
                all_console = driver.read_console_errors()
                console_errors = all_console[console_seen:]
                console_seen = len(all_console)
```

(the rest of the loop already uses `console_errors` for both the action dict and `console_oracle` — unchanged).

(d) Persist the invoke log: the final `return` (line 224) becomes:

```python
    return {"journey_id": journey_id, "actions": actions, "candidates": candidates,
            "state_evidence": state_evidence, "invoke_log": invoke_log}
```

(`invoke_log` is already read at line 206.)

- [ ] **Step 4: Run the full suite, commit**

Run: `python3 -m pytest hack/dogfood/ -q` → ALL PASS (Task 7 already added `invoke_log` to the schema).

```bash
git add hack/dogfood/gui/run_gui_journeys.py hack/dogfood/gui/test_run_gui_journeys.py
git commit -m "feat(dogfood): GUI runner persists invoke log, dedups console errors, flags model infra

The invoke log (evidence behind silent_failure verdicts) was read and
dropped — the skeptic couldn't audit those verdicts; console errors were
re-counted cumulatively on every action; a model transport failure ended
the step with no trace. All three now land honestly in the bundle.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 10: dogfood.yml — setup job, dynamic matrices, journeys_path, weekly cron, evidence paths, job summary

**Files:**
- Modify: `.github/workflows/dogfood.yml`, `.claude/skills/llm-dogfooding/scripts/dispatch-swarm.sh`
- Create: `hack/dogfood/summarize_bundle.py`
- Test: `hack/dogfood/test_summarize.py`

**Interfaces:**
- Produces: workflow input `journeys_path` (default `journeys.json`); weekly cron (Mon 06:00 UTC) running `hack/dogfood/journeys/smoke-core-cli.json` on `main`; `setup` job with outputs `journeys_path`, `cli_shards`, `gui_shards`, `cli_matrix` (JSON array), `gui_matrix`, `has_gui` (`"true"|"false"`); `summarize_bundle.py <bundle.json>` prints a markdown table (journeys / positive / flipping / infra / unreached / soft).

- [ ] **Step 1: Write `summarize_bundle.py` test-first**

Create `hack/dogfood/test_summarize.py`:

```python
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


class SummarizeTests(unittest.TestCase):
    def test_summary_table(self):
        bundle = {"shard": 1, "feature": "f", "results": [
            {"journey_id": "good", "actions": [{"command": "x", "exit_code": 0}],
             "candidates": []},
            {"journey_id": "dead", "actions": [], "candidates": [
                {"kind": "infra", "detail": "d", "violated_expectation": "",
                 "source": "", "trajectory_ref": {"journey_id": "dead",
                                                  "action_index": -1}}]},
            {"journey_id": "shallow", "actions": [], "candidates": [
                {"kind": "unreached_decisive", "detail": "d",
                 "violated_expectation": "", "source": "",
                 "trajectory_ref": {"journey_id": "shallow",
                                    "action_index": -1}}]},
        ]}
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "traj-1.json")
            with open(p, "w") as f:
                json.dump(bundle, f)
            out = subprocess.run(
                [sys.executable, os.path.join(HERE, "summarize_bundle.py"), p],
                capture_output=True, text=True, check=True).stdout
        self.assertIn("| journeys | positive | flipping | infra | unreached | soft |", out)
        self.assertIn("| 3 | 1 | 2 | 1 | 1 | 0 |", out)
        self.assertIn("dead", out)      # per-journey verdict lines
        self.assertIn("unreached", out)


if __name__ == "__main__":
    unittest.main()
```

Run: `python3 -m pytest hack/dogfood/test_summarize.py -q` → FAIL (script absent).

Create `hack/dogfood/summarize_bundle.py`:

```python
#!/usr/bin/env python3
"""Render a one-bundle markdown summary for $GITHUB_STEP_SUMMARY.

Usage: summarize_bundle.py <traj.json> [...more bundles]

Mirrors the collector's flipping rule (soft = latency + non-decisive
functional; everything else flips) so the CI job summary and the Phase-3
tally agree. Pure stdlib; report-only (a malformed bundle prints a warning
row instead of failing the step)."""
from __future__ import annotations

import json
import sys


def _flips(c: dict) -> bool:
    kind = c.get("kind", "?")
    if kind == "latency":
        return False
    if kind == "functional":
        return bool(c.get("decisive"))
    return True


def summarize(paths: list[str]) -> str:
    rows = []
    tot = {"j": 0, "pos": 0, "flip": 0, "infra": 0, "unreached": 0, "soft": 0}
    for path in paths:
        try:
            with open(path) as f:
                bundle = json.load(f)
        except (OSError, ValueError) as e:
            rows.append(f"| `{path}` | ⚠ unreadable: {e} |")
            continue
        for r in bundle.get("results", []):
            tot["j"] += 1
            cands = r.get("candidates", []) or []
            kinds = [c.get("kind") for c in cands]
            n_flip = sum(1 for c in cands if _flips(c))
            tot["flip"] += n_flip
            tot["soft"] += len(cands) - n_flip
            verdict = "✅ positive"
            if "infra" in kinds:
                tot["infra"] += 1
                verdict = "🔌 infra"
            elif "unreached_decisive" in kinds:
                tot["unreached"] += 1
                verdict = "❓ unreached"
            elif n_flip:
                verdict = "❌ flipped"
            else:
                tot["pos"] += 1
            rows.append(f"| `{r.get('journey_id')}` | {verdict} | "
                        f"{len(r.get('actions') or [])} actions | "
                        f"{n_flip} flipping / {len(cands) - n_flip} soft |")
    head = ("| journeys | positive | flipping | infra | unreached | soft |\n"
            "|---|---|---|---|---|---|\n"
            f"| {tot['j']} | {tot['pos']} | {tot['flip']} | {tot['infra']} "
            f"| {tot['unreached']} | {tot['soft']} |\n")
    return head + "\n| journey | verdict | depth | candidates |\n|---|---|---|---|\n" \
        + "\n".join(rows) + "\n"


def main(argv=None) -> int:
    args = (argv if argv is not None else sys.argv[1:])
    if not args:
        print("usage: summarize_bundle.py <traj.json>...", file=sys.stderr)
        return 2
    print(summarize(args))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

Run: `python3 -m pytest hack/dogfood/test_summarize.py -q` → PASS. Adjust the expected table row if the verdict precedence differs — the precedence is: infra > unreached > flipped > positive. (In the test bundle: `dead` has an infra candidate which also flips → flip count 1 from infra + 1 from unreached = 2.)

- [ ] **Step 2: Rework `dogfood.yml`**

Apply ALL of the following (keep everything else byte-identical; the artifact-build jobs are untouched):

(a) Triggers + inputs (lines 17-35) →

```yaml
on:
  workflow_dispatch:
    inputs:
      journeys_path:
        description: 'Path (in the dispatched ref) of the journeys file to run'
        required: false
        default: 'journeys.json'
      shards:
        description: 'Number of CLI journey shards'
        required: false
        default: '3'
      gui_shards:
        description: 'Number of GUI journey shards (GUI jobs are skipped when the journey set has no modality:"gui" entries)'
        required: false
        default: '3'
      model:
        description: 'OpenRouter model id (cheap but tool-capable by default; deepseek-chat was too weak to drive the shell-agent loop reliably)'
        required: false
        default: 'google/gemini-2.5-flash'
      max_usd:
        description: 'PER-SHARD estimated USD cap (worst-case total = max_usd × (cli shards + gui shards))'
        required: false
        default: '2'
  schedule:
    # Weekly novice smoke probe on main: the committed smoke corpus, report-only
    # (owner decision 2026-07-04: manual/weekly only — no push trigger).
    - cron: '0 6 * * 1'
```

(b) New `setup` job (insert before `kernel`):

```yaml
jobs:
  # Derive the shard matrices from the inputs + the journey set, so the shard
  # count is a real knob (the old hardcoded 3-shard matrices killed dispatches
  # with any other value) and the GUI jobs are skipped entirely when the set
  # has no modality:"gui" journeys (3 wasted Tauri builds otherwise).
  setup:
    name: plan shards
    runs-on: ubuntu-latest
    timeout-minutes: 5
    outputs:
      journeys_path: ${{ steps.plan.outputs.journeys_path }}
      cli_shards: ${{ steps.plan.outputs.cli_shards }}
      gui_shards: ${{ steps.plan.outputs.gui_shards }}
      cli_matrix: ${{ steps.plan.outputs.cli_matrix }}
      gui_matrix: ${{ steps.plan.outputs.gui_matrix }}
      has_gui: ${{ steps.plan.outputs.has_gui }}
    steps:
      - uses: actions/checkout@9f698171ed81b15d1823a05fc7211befd50c8ae0 # v6.0.3
      - id: plan
        env:
          # schedule fires with empty inputs -> smoke-corpus defaults.
          JOURNEYS_PATH: ${{ github.event_name == 'schedule' && 'hack/dogfood/journeys/smoke-core-cli.json' || inputs.journeys_path || 'journeys.json' }}
          SHARDS: ${{ inputs.shards || '3' }}
          GUI_SHARDS: ${{ inputs.gui_shards || '3' }}
        run: |
          python3 - <<'EOF'
          import json, os
          jp = os.environ["JOURNEYS_PATH"]
          shards = max(1, int(os.environ["SHARDS"]))
          gui_shards = max(1, int(os.environ["GUI_SHARDS"]))
          with open(jp) as f:
              doc = json.load(f)
          journeys = doc.get("journeys", []) or []
          n_gui = sum(1 for j in journeys if j.get("modality") == "gui")
          n_cli = len(journeys) - n_gui
          shards = min(shards, n_cli) or 1
          gui_shards = min(gui_shards, n_gui) or 1
          out = os.environ["GITHUB_OUTPUT"]
          with open(out, "a") as f:
              f.write(f"journeys_path={jp}\n")
              f.write(f"cli_shards={shards}\n")
              f.write(f"gui_shards={gui_shards}\n")
              f.write(f"cli_matrix={json.dumps(list(range(shards)))}\n")
              f.write(f"gui_matrix={json.dumps(list(range(gui_shards)))}\n")
              f.write(f"has_gui={'true' if n_gui else 'false'}\n")
          print(f"{jp}: {n_cli} cli journeys -> {shards} shards; "
                f"{n_gui} gui journeys -> {gui_shards} shards")
          EOF
```

(c) `dogfood` job: `needs: [setup, kernel, initramfs]`; DELETE the "Guard — matrix is fixed at 3 shards" step (lines 209-216); matrix →

```yaml
    strategy:
      fail-fast: false
      matrix:
        shard: ${{ fromJson(needs.setup.outputs.cli_matrix) }}
```

Run-step env: `SHARDS: ${{ needs.setup.outputs.cli_shards }}`, add `JOURNEYS_PATH: ${{ needs.setup.outputs.journeys_path }}`, and `MODEL: ${{ inputs.model || 'google/gemini-2.5-flash' }}`, `MAX_USD: ${{ inputs.max_usd || '2' }}` (schedule fallbacks). In the script: `--journeys "$JOURNEYS_PATH"`.

After the run step, add the summary step, and fix the failure-log path:

```yaml
      - name: Job summary
        if: always()
        run: python3 hack/dogfood/summarize_bundle.py "traj-$SHARD.json" >> "$GITHUB_STEP_SUMMARY" || true
        env:
          SHARD: ${{ matrix.shard }}
      - name: Upload sandbox logs on failure
        if: failure()
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: dogfood-${{ matrix.shard }}-failure-logs
          path: |
            /tmp/izd-${{ matrix.shard }}/*/sandboxes/*/logs/*
          if-no-files-found: ignore
```

(The old path `${{ runner.temp }}/izba-dogfood-*` matched nothing — the data dir moved to `/tmp/izd-$SHARD` for SUN_LEN; per-journey dirs sit one level below it.)

(d) `dogfood-gui` job: `needs: [setup, kernel, initramfs]`; add `if: needs.setup.outputs.has_gui == 'true'`; DELETE its guard step (lines 346-352); matrix → `shard: ${{ fromJson(needs.setup.outputs.gui_matrix) }}`; env `GUI_SHARDS: ${{ needs.setup.outputs.gui_shards }}`, `JOURNEYS_PATH: ${{ needs.setup.outputs.journeys_path }}`, model/max_usd fallbacks as above; `--journeys "$JOURNEYS_PATH"`. Add the same summary step (`gui-traj-$SHARD.json`) and a failure-log upload for `/tmp/izd-gui-${{ matrix.shard }}/*/sandboxes/*/logs/*`.

(e) Header comment (lines 3-15): note the weekly schedule + journeys_path + that `max_usd` is per-shard.

- [ ] **Step 3: Validate the workflow YAML**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/dogfood.yml')); print('yaml ok')"`
Expected: `yaml ok`. Also run `python3 -m pytest hack/dogfood/ -q` → ALL PASS.

- [ ] **Step 4: Update `dispatch-swarm.sh`**

In `.claude/skills/llm-dogfooding/scripts/dispatch-swarm.sh`: where `max_usd` is passed/documented (line ~18 default + the `gh workflow run` call), update the comment/echo to state it is PER-SHARD and print the worst-case total: `echo "budget: \$${MAX_USD}/shard (worst case \$$((MAX_USD * (SHARDS + 3))) if GUI runs)"` — read the script first and keep its var names; the substance is: per-shard semantics stated, worst-case printed, and a note that GUI jobs auto-skip when the tier has no gui journeys.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/dogfood.yml hack/dogfood/summarize_bundle.py hack/dogfood/test_summarize.py .claude/skills/llm-dogfooding/scripts/dispatch-swarm.sh
git commit -m "fix(ci): dynamic dogfood shard matrices, honest budgets, working evidence paths

- setup job derives matrices from inputs + the journey set; GUI jobs skip
  when no modality:gui journeys (the hardcoded-3 guard killed both
  2026-07-02 runs and burned 3 Tauri builds on CLI-only tiers)
- journeys_path input + weekly Monday cron running the committed smoke
  corpus on main (report-only)
- max_usd re-documented as per-shard (it always was; the 'cumulative'
  description under-stated worst case 6x)
- failure-log artifact path pointed at the real /tmp/izd-* data dirs
  (the runner.temp glob matched nothing since the SUN_LEN move)
- per-shard job summary table (summarize_bundle.py, tested)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 11: standing smoke corpus

**Files:**
- Create: `hack/dogfood/journeys/smoke-core-cli.json`
- Test: `hack/dogfood/test_corpus.py`

**Interfaces:**
- Consumes: `hack/dogfood/fixtures/journeys.smoke-core-cli.json` (seed), `journeys.schema.json`.
- Produces: the committed corpus the weekly cron runs (Task 10's schedule fallback path points here).

- [ ] **Step 1: Write the failing test**

Create `hack/dogfood/test_corpus.py`:

```python
"""The committed smoke corpus must stay schema-valid and novice-shaped:
goal-achievement oracles only, no gui journeys (the weekly cron runs the CLI
smoke), every journey shallow (<= 4 steps)."""
import json
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(HERE, "journeys", "smoke-core-cli.json")


class SmokeCorpusTests(unittest.TestCase):
    def _load(self):
        with open(CORPUS) as f:
            return json.load(f)

    def test_validates_against_schema(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema not installed")
        with open(os.path.join(HERE, "schema", "journeys.schema.json")) as f:
            schema = json.load(f)
        jsonschema.validate(self._load(), schema)

    def test_novice_shape(self):
        doc = self._load()
        self.assertGreaterEqual(len(doc["journeys"]), 7)
        for j in doc["journeys"]:
            self.assertNotEqual(j.get("modality"), "gui", j["journey_id"])
            self.assertLessEqual(len(j["steps"]), 4, j["journey_id"])
```

Run: `python3 -m pytest hack/dogfood/test_corpus.py -q` → FAIL (file absent).

- [ ] **Step 2: Create the corpus**

Copy the 5 journeys from `hack/dogfood/fixtures/journeys.smoke-core-cli.json` (READ IT — reuse its journeys verbatim, they are already calibrated) into `hack/dogfood/journeys/smoke-core-cli.json` with `"feature": "core-cli-smoke"`, then append these 3 novice journeys (adjust `source.ref` wording to match the fixture's style):

```json
    {
      "journey_id": "publish-a-port",
      "rationale": "README promises host access to guest services via port publishing; a novice must find the verb from --help alone.",
      "source": { "kind": "readme", "ref": "README port publishing section" },
      "tier": "smoke",
      "steps": [
        { "intent": "Start a sandbox running a small web server inside the guest",
          "expect": "sandbox is running" },
        { "intent": "Expose the guest server's port to the host and fetch a page from the host side",
          "expect": "an HTTP response arrives on the published host port", "core": true }
      ]
    },
    {
      "journey_id": "attach-a-volume",
      "rationale": "Named volumes persist across sandbox recreation; a novice should manage them from documented verbs.",
      "source": { "kind": "help", "ref": "izba volume --help" },
      "tier": "smoke",
      "steps": [
        { "intent": "Create a sandbox with a named persistent volume mounted at a guest path and write a file into it",
          "expect": "the file exists inside the guest at the volume path" },
        { "intent": "Remove the sandbox, recreate it with the same volume, and check the file is still there",
          "expect": "the file survives sandbox recreation", "core": true }
      ]
    },
    {
      "journey_id": "view-firewall-activity",
      "rationale": "The egress firewall's audit log is a headline feature; a novice should reach it from --help.",
      "source": { "kind": "help", "ref": "izba netlog --help" },
      "tier": "smoke",
      "steps": [
        { "intent": "Start a sandbox and make an outbound network request from inside the guest",
          "expect": "the request completes (or is denied by policy)" },
        { "intent": "Look at what network activity izba recorded for that sandbox",
          "expect": "the audit log shows the connection with an allow/deny verdict", "core": true }
      ]
    }
```

Run: `python3 -m pytest hack/dogfood/test_corpus.py -q` → PASS.

- [ ] **Step 3: Commit**

```bash
git add hack/dogfood/journeys/smoke-core-cli.json hack/dogfood/test_corpus.py
git commit -m "feat(dogfood): standing novice smoke corpus for the weekly probe

8 shallow CLI journeys (lifecycle, exec, ports, volumes, netlog) whose
only oracle is goal-achievement from the public surface — the one journey
set that persists across runs (spec §1 freshness principle). Runs weekly
via dogfood.yml's schedule; schema-validated in pytest.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 12: skeptic-verdict schema + signal/noise ledger

**Files:**
- Create: `hack/dogfood/schema/skeptic-verdict.schema.json`, `.claude/skills/llm-dogfooding/scripts/append-ledger.py`
- Test: `hack/dogfood/test_ledger.py`

**Interfaces:**
- Produces: `skeptic-verdict.json` contract (consumed by Task 14's agent doc + the orchestrator): `{feature, tier, findings: [{id, class, severity, fix_routing, summary, journey_ids, anchor}], capabilities: {established: [], blocked: []}, counts: {kept, refuted, cheated, inconclusive}}`. `append-ledger.py --collected collected.json [--verdict skeptic-verdict.json] --feature F --tier T [--ledger PATH]` appends one JSON line to `hack/dogfood/ledger.jsonl`.

- [ ] **Step 1: Write the schema**

Create `hack/dogfood/schema/skeptic-verdict.schema.json`:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://github.com/Lupus/izba/hack/dogfood/schema/skeptic-verdict.schema.json",
  "title": "izba dogfood skeptic verdict (Phase 3 machine-readable output)",
  "description": "Emitted by the trajectory-skeptic agent ALONGSIDE its human report.md. The orchestrator routes fixes from `findings[].fix_routing`, gates tiers on `capabilities`, and append-ledger.py reads `counts` — no prose parsing.",
  "type": "object",
  "additionalProperties": false,
  "required": ["feature", "findings", "counts"],
  "properties": {
    "feature": { "type": "string" },
    "tier": { "type": "string", "enum": ["smoke", "core", "deep"] },
    "findings": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["id", "class", "summary", "journey_ids"],
        "properties": {
          "id": { "type": "string", "description": "Stable kebab-case finding id (e.g. 'volume-size-suffix-undocumented')." },
          "class": {
            "type": "string",
            "enum": ["real", "intended", "self-inflicted", "discoverability", "cheating", "unverified", "inconclusive", "harness"],
            "description": "Direction-A candidate classes (real/intended/self-inflicted/discoverability), Direction-B green-audit classes (cheating/unverified/inconclusive), or 'harness' (the finding is about the dogfood harness itself)."
          },
          "severity": { "type": "string", "enum": ["P1", "P2", "P3"] },
          "fix_routing": {
            "type": "string",
            "enum": ["auto-fixable", "escalate", "none"],
            "description": "auto-fixable = within the in-place fix boundary (docs/help/error wording/harness); escalate = behavior/security/contract, record as blocker; none = dropped/informational."
          },
          "summary": { "type": "string" },
          "journey_ids": { "type": "array", "items": { "type": "string" } },
          "anchor": { "type": "string", "description": "Spec/PR/review citation grounding the verdict." }
        }
      }
    },
    "capabilities": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "established": { "type": "array", "items": { "type": "string" } },
        "blocked": { "type": "array", "items": { "type": "string" } }
      }
    },
    "counts": {
      "type": "object",
      "additionalProperties": false,
      "required": ["kept", "refuted"],
      "properties": {
        "kept": { "type": "integer", "description": "Candidates confirmed real (incl. discoverability)." },
        "refuted": { "type": "integer", "description": "Candidates dropped as intended/self-inflicted." },
        "cheated": { "type": "integer", "description": "Positive journeys found cheated/unverified." },
        "inconclusive": { "type": "integer" }
      }
    }
  }
}
```

- [ ] **Step 2: Write the failing ledger test**

Create `hack/dogfood/test_ledger.py`:

```python
"""append-ledger.py: one JSON line per run into hack/dogfood/ledger.jsonl."""
import importlib.util
import json
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def _load_script():
    repo_root = os.path.dirname(os.path.dirname(HERE))
    path = os.path.join(repo_root, ".claude", "skills", "llm-dogfooding",
                        "scripts", "append-ledger.py")
    if not os.path.isfile(path):
        return None
    spec = importlib.util.spec_from_file_location("append_ledger", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class LedgerTests(unittest.TestCase):
    def test_appends_one_json_line(self):
        mod = _load_script()
        if mod is None:
            self.skipTest("append-ledger.py not present")
        with tempfile.TemporaryDirectory() as d:
            collected = os.path.join(d, "collected.json")
            json.dump({"totals": {"journeys": 8, "candidates": 5,
                                  "flipping_candidates": 2, "soft_candidates": 3,
                                  "positive_journeys": 6, "infra_journeys": 0,
                                  "unreached_journeys": 1,
                                  "by_kind": {"functional": 5}}},
                      open(collected, "w"))
            verdict = os.path.join(d, "verdict.json")
            json.dump({"feature": "f", "findings": [],
                       "counts": {"kept": 1, "refuted": 1}}, open(verdict, "w"))
            ledger = os.path.join(d, "ledger.jsonl")
            rc = mod.main(["--collected", collected, "--verdict", verdict,
                           "--feature", "f", "--tier", "smoke",
                           "--ledger", ledger])
            self.assertEqual(rc, 0)
            rc = mod.main(["--collected", collected, "--feature", "f",
                           "--tier", "core", "--ledger", ledger])
            self.assertEqual(rc, 0)
            lines = [json.loads(x) for x in open(ledger).read().splitlines()]
            self.assertEqual(len(lines), 2)
            self.assertEqual(lines[0]["feature"], "f")
            self.assertEqual(lines[0]["tier"], "smoke")
            self.assertEqual(lines[0]["totals"]["journeys"], 8)
            self.assertEqual(lines[0]["skeptic"]["kept"], 1)
            self.assertNotIn("skeptic", lines[1])  # verdict optional
            self.assertIn("date", lines[0])
```

Run: `python3 -m pytest hack/dogfood/test_ledger.py -q` → FAIL (script absent).

- [ ] **Step 3: Write `append-ledger.py`**

Create `.claude/skills/llm-dogfooding/scripts/append-ledger.py`:

```python
#!/usr/bin/env python3
"""append-ledger.py — append one run's signal/noise tallies to the ledger.

Usage:
  append-ledger.py --collected collected.json [--verdict skeptic-verdict.json]
                   --feature <name> --tier <smoke|core|deep>
                   [--ledger hack/dogfood/ledger.jsonl]

One JSON line per dogfood run (Phase-4 step in the skill). The ledger is how
"iterate until signal/noise stabilizes" becomes measurable across runs:
candidate counts, precision (kept vs refuted), and depth (positives vs
unreached) over time. Report-only utility; never mutates existing lines."""
from __future__ import annotations

import argparse
import datetime
import json
import os
import sys


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--collected", required=True,
                    help="collect-trajectories.py --json output")
    ap.add_argument("--verdict", default=None,
                    help="optional skeptic-verdict.json (schema/skeptic-verdict.schema.json)")
    ap.add_argument("--feature", required=True)
    ap.add_argument("--tier", required=True)
    ap.add_argument("--ledger", default="hack/dogfood/ledger.jsonl")
    args = ap.parse_args(argv)

    with open(args.collected) as f:
        totals = json.load(f).get("totals", {})
    entry = {
        "date": datetime.date.today().isoformat(),
        "feature": args.feature,
        "tier": args.tier,
        "totals": totals,
    }
    if args.verdict:
        with open(args.verdict) as f:
            entry["skeptic"] = json.load(f).get("counts", {})
    os.makedirs(os.path.dirname(os.path.abspath(args.ledger)), exist_ok=True)
    with open(args.ledger, "a") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")
    print(f"appended {args.feature}/{args.tier} to {args.ledger}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

Run: `python3 -m pytest hack/dogfood/test_ledger.py -q` → PASS. Full suite: `python3 -m pytest hack/dogfood/ -q` → ALL PASS.

- [ ] **Step 4: Commit**

```bash
git add hack/dogfood/schema/skeptic-verdict.schema.json .claude/skills/llm-dogfooding/scripts/append-ledger.py hack/dogfood/test_ledger.py
git commit -m "feat(dogfood): machine-readable skeptic verdict schema + signal/noise ledger

skeptic-verdict.json replaces prose parsing for fix-routing/capability
gating; append-ledger.py accretes one JSON line per run into
hack/dogfood/ledger.jsonl so 'iterate until signal/noise stabilizes' is
measurable across runs instead of vibes.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 13: `docs/dogfooding-value.md` + CLAUDE.md documentation-map row

**Files:**
- Create: `docs/dogfooding-value.md`
- Modify: `CLAUDE.md` (documentation-map table)

This doc is the owner-requested durable capture of the placement model. Write it from **spec §1** (`docs/superpowers/specs/2026-07-04-dogfood-instrument-honesty-design.md`), which holds the owner-locked decisions verbatim. Required sections (each 1-3 paragraphs, concrete, no filler):

1. **What the harness measures** — e2e asserts what the product does (behavior under perfect knowledge); the swarm measures what a user can get the product to do (behavior under realistic ignorance, README + `--help` only). The delta = UX/docs debt; inexpressible as a deterministic test. The five unique finding classes: discoverability gaps, error-message quality (the Actor's next move after an error measures whether the error teaches recovery), workflow friction, first-contact bugs on unanticipated paths (cite izba#71 SUN_LEN), UI-lies-about-state.
2. **The cheap model is the instrument** — calibrated ignorance; a smarter swarm model would paper over the gaps an expert papers over; Opus phases run locally on the owner's subscription and moving them to API-billed CI is a cost regression.
3. **The fair-test boundary is the anti-overlap mechanism** — journeys carry intent, never commands; a journey structurally cannot degrade into a unit test.
4. **No e2e exclusion map** (decision record, 2026-07-03): e2e coverage never subtracts journeys; the swarm failing a scenario e2e proves wired is exactly the differential; e2e can happily pin a confusing UX.
5. **Graduation, not accretion** — behavioral finding → fix + distilled deterministic e2e test (the trajectory is the repro); UX finding → docs/help fix or issue; the dogfood corpus never becomes a frozen regression suite.
6. **Freshness principle + the one standing corpus** — deep journeys are disposable by design; what persists: findings→issues, graduated e2e tests, the ledger (`hack/dogfood/ledger.jsonl`), and the novice smoke corpus (`hack/dogfood/journeys/smoke-core-cli.json`, weekly cron, goal-achievement oracle only).
7. **Instrument honesty over determinism** — the harness need not be deterministic (usability is a distribution) but a green must mean the assertion was reached and corroborated; name the guarantees: `infra` candidates + exit 3, `unreached_decisive`, `reconcile_violation`, `guest_console`, `expect_cmd_re`/`graded_cmd`.
8. **Where things live** — table: skill (`.claude/skills/llm-dogfooding/`), harness (`hack/dogfood/`), CI (`.github/workflows/dogfood.yml`), schemas, ledger, smoke corpus, this doc.

End with: "Future harness work MUST be checked against this model — a proposal that turns journeys into frozen regression tests, moves the Opus phases to API-billed CI, or subtracts journeys because e2e covers them is fighting the design, not improving it."

CLAUDE.md documentation-map: add a row after the egress-firewall-building-blocks row:

```markdown
| [docs/dogfooding-value.md](docs/dogfooding-value.md) | **LLM-dogfooding value model** — what the swarm harness measures vs e2e tests, the fair-test boundary, graduation/freshness principles, and the instrument-honesty guarantees. Read before changing `hack/dogfood/` or the `llm-dogfooding` skill. |
```

- [ ] Write the doc; verify every claim against spec §1; `git add docs/dogfooding-value.md CLAUDE.md && git commit -m "docs(dogfood): capture the dogfooding value model (vs e2e) as a durable doc

Owner-requested (2026-07-04): the placement model — e2e asserts behavior,
the swarm measures user-achievability — plus the fair-test/graduation/
freshness principles and the instrument-honesty guarantees, so future
harness work aligns with the vision instead of re-deriving it.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"`

---

### Task 14: skill + agent + local-harness updates

**Files:**
- Modify: `.claude/skills/llm-dogfooding/SKILL.md`, `.claude/skills/llm-dogfooding/references/methodology.md`, `.claude/agents/journey-compiler.md`, `.claude/agents/trajectory-skeptic.md`, `.claude/agents/dogfood-gap-fixer.md`, `hack/dogfood/local-harness.md`

Read each file fully before editing. The changes (apply ALL):

**SKILL.md:**
- Phase 4 ("Land") gains two steps: *(a) Graduation:* "for each confirmed **behavioral** finding, land a distilled deterministic e2e test alongside the fix (the trajectory is the repro) — behaviors get pinned in the e2e layer, never by freezing journeys; UX findings land as docs/help fixes or issues." *(b) Ledger:* "append the run's tallies: `scripts/append-ledger.py --collected collected.json --verdict skeptic-verdict.json --feature <f> --tier <t>` (ledger: `hack/dogfood/ledger.jsonl`)."
- Quick-reference table: add rows for `append-ledger.py`, the smoke corpus (`hack/dogfood/journeys/smoke-core-cli.json` — weekly cron + `journeys_path` input), `summarize_bundle.py`, and the value doc (`docs/dogfooding-value.md`).
- Common mistakes: add "**Turning journeys into regression tests** — deep journeys are disposable by design (see docs/dogfooding-value.md); recompile against today's surface instead of re-running stale sets. The only standing corpus is the novice smoke probe." and "**Subtracting journeys because e2e covers the behavior** — e2e coverage never subtracts journeys; the swarm failing an e2e-proven scenario IS the discoverability signal."

**references/methodology.md:**
- In "The deterministic oracle" section, document the new kinds: `infra` (model/API failure — harness-verified, exits 3 when >50% of journeys degrade), `unreached_decisive` (#126), `reconcile_violation`, `guest_console`; and `expect_cmd_re`/`graded_cmd` (grade the intent-bearing action).
- The "find → improve → re-find" loop section: reference the ledger as the way signal/noise maturation is now tracked (replacing the from-memory "18 → 13 → 6" style of tracking).
- Link `docs/dogfooding-value.md` from the top ("the placement model this method serves").

**journey-compiler.md:**
- Authoring guidance: `expect_cmd_re` on refusal/`expect_exit` steps (anchor to the distinctive token of the command under test, never a full command line); note it lives in journeys.json which the swarm never sees.
- Add the rule verbatim: "**e2e coverage never subtracts journeys.** Do not skip a journey because an e2e test proves the behavior wired — the swarm failing an e2e-proven scenario is exactly the discoverability differential this method measures."

**trajectory-skeptic.md:**
- New kinds table: `infra`, `unreached_decisive`, `reconcile_violation`, `guest_console` are **harness-verified facts, not refutable claims** — triage them as infra/inconclusive/product findings respectively, don't try to refute the oracle.
- Output contract: emit `skeptic-verdict.json` conforming to `hack/dogfood/schema/skeptic-verdict.schema.json` ALONGSIDE the human `report.md`; the orchestrator consumes the JSON (fix-routing, capability verdict, counts), the human reads the markdown.
- Note `graded_cmd` on functional candidates and `invoke_log` in GUI bundles as new evidence.

**dogfood-gap-fixer.md:**
- Input contract: the orchestrator passes ONE finding object from `skeptic-verdict.json` (id/class/fix_routing/summary/journey_ids/anchor) instead of prose.

**local-harness.md:**
- Exit-code table: `0` = ran (findings are report-only), `2` = usage/startup error, `3` = catastrophic infra (>50% journeys degraded — check OPENROUTER_API_KEY first).
- Replace the stale inline skeptic prompt template (lines ~175-205) with: "Dispatch the `trajectory-skeptic` agent (`.claude/agents/trajectory-skeptic.md`) — it emits `report.md` + `skeptic-verdict.json` (schema: `hack/dogfood/schema/skeptic-verdict.schema.json`). The old inline template predates the discoverability class, the Direction-B green audit, and the JSON contract."
- Document the smoke corpus + weekly cron + `journeys_path`, `summarize_bundle.py`, and `append-ledger.py`.

- [ ] Apply all edits; run `python3 -m pytest hack/dogfood/ -q` (unchanged code, sanity); commit:

```bash
git add .claude/skills/llm-dogfooding/ .claude/agents/journey-compiler.md .claude/agents/trajectory-skeptic.md .claude/agents/dogfood-gap-fixer.md hack/dogfood/local-harness.md
git commit -m "docs(dogfood): align skill + agents with the new harness mechanics

Graduation + ledger steps in Phase 4, new candidate kinds documented as
harness-verified facts, skeptic emits machine-readable skeptic-verdict.json,
gap-fixer consumes finding objects, expect_cmd_re authoring guidance +
the e2e-never-subtracts rule in the compiler, honest exit-code table and
de-staled skeptic template in local-harness.md.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 15 (ORCHESTRATOR — not a subagent task): gates, PR, verification swarms, skill e2e

- [ ] Full gate run (unsandboxed where needed): `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check` (should be untouched-green: no Rust changes), `python3 -m pytest hack/dogfood/ -q`, YAML lint of dogfood.yml.
- [ ] Push `worktree-dogfood-instrument-honesty`, open the PR (attribution trailer), watch checks incl. SonarCloud; `/greploop` if Greptile objects.
- [ ] **Verification swarms** (spec §8): (1) local bad-key canary → exit 3 + infra candidates; (2) local fake-model unreached-decisive replay; (3) dispatch `dogfood.yml` off the PR branch with `journeys_path=hack/dogfood/journeys/smoke-core-cli.json` → honest tallies in the job summary; (4) GUI skeleton dispatch → `gui-traj-*` collected + invoke_log present.
- [ ] **Fresh-context skill e2e** (spec §8.5): dispatch subagents that read ONLY the updated SKILL.md/methodology and drive compile → sequence → dispatch → collect → skeptic-verdict.json on a small feature; their confusion = doc bugs to fix before merge.

## Self-Review Notes

- Spec coverage: §3.1→T1+T2, §3.2→T3, §3.3→T4, §3.4→T5, §3.5+§3.6→T6, §3.7→T1(d in T2)/T7, §3.8→T7, §4→T10, §5→T10+T11, §6→T12+T13+T14, §7→T9, §8→T15. D1→T13.
- Type consistency: `_infra_candidate` defined twice by design (run_journeys.py + run_gui_journeys.py, identical shape — the GUI runner deliberately avoids importing more from run_journeys). Candidate kinds are exact strings everywhere; `graded_cmd` only on functional candidates; collector treats unknown kinds as flipping (so ordering of Tasks 2-8 never drops findings).
- Tasks 1-9 are pure-Python TDD; Task 10 is YAML + one tested helper; 11-12 tested; 13-14 docs with concrete content requirements anchored to spec §1.
