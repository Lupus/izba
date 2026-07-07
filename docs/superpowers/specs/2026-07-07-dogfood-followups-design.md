# Dogfood instrument-honesty follow-ups — design

**Date:** 2026-07-07
**Status:** approved (scope pre-approved by owner as the deferred follow-ups of
PR #127; see `docs/superpowers/specs/2026-07-04-dogfood-instrument-honesty-design.md`)

## 1. Problem

PR #127 (dogfood instrument honesty) shipped with four accepted-non-blocking
follow-ups, confirmed by reviewers and by live swarm runs. Each is a residual
false-green or blind-spot path:

- **F1 — GUI runner never fails catastrophically.**
  `hack/dogfood/gui/run_gui_journeys.py::main()` always returns 0. A dead
  OPENROUTER key or a sidecar that never comes up on a GUI shard produces a
  green-but-degraded job — exactly the class of silent failure the CLI runner's
  exit-3 backstop exists to prevent. The inputs already exist (GUI journeys
  carry `infra` candidates on model error, sidecar startup failure, and journey
  crash); only the accounting and exit code are missing.
- **F2 — CLI shards run GUI journeys.** `run_journeys.py::main()` shards over
  ALL journeys; in the gui-skeleton dispatch (run 28702359469) the CLI job ran
  the five `modality:"gui"` journeys as CLI journeys (the model typed
  `izba exec -it web -- /bin/bash` for a GUI intent). Symmetrically,
  `dogfood.yml` has `has_gui` to skip GUI jobs for CLI-only corpora but no
  `has_cli` to skip the (KVM-heavy) CLI job for all-GUI sets.
- **F3 — invoke_log (and console errors) empty on real GUI runs.** Live
  gui-skeleton bundles showed journeys with 3 actions but `invoke_log: []`.
  Root cause **confirmed empirically** (agent-browser 0.25.4 local probe;
  `parse_snapshot` already handles the same envelope for 0.31.1):
  `agent-browser eval --json` returns
  `{"success":true,"data":{"origin":...,"result":<value-or-json-string>},"error":null}`
  — the value is nested under `data.result`, but `driver.py::_eval_json` only
  unwraps a top-level `result` key, so it returns the whole envelope dict and
  both `read_invoke_log()` and `read_console_errors()` collapse to `[]`. The
  GUI console oracle has therefore been blind on every real run, not just the
  invoke log / silent-failure oracle.
- **F4 — collector `totals.by_kind` is modality-blind.** Per spec §10 of the
  instrument-honesty design (non-normative note), rows in
  `collect-trajectories.py` carry `modality` but the aggregate `by_kind`
  Counter is flat, so a skeptic reading `collected.json` cannot see whether
  e.g. all `reconcile_violation`s came from the GUI side.

## 2. Design

One PR, four small changes, all TDD (stdlib-only Python, same conventions as
PR #127).

### F1 — GUI catastrophic-infra backstop

`gui/run_gui_journeys.py` imports `CATASTROPHIC_DEGRADED_FRACTION` and
`EXIT_CATASTROPHIC_INFRA` from `run_journeys` (it already imports
`select_shard`/`_journey_data_dir`/`BudgetExceeded` from there — a single
source of truth, no re-declaration). `main()` mirrors the CLI accounting
verbatim:

```python
degraded = sum(
    1 for r in results
    if not r.get("actions")
    or any(c.get("kind") == "infra" for c in r.get("candidates", []))
)
catastrophic = bool(results) and degraded / len(results) > CATASTROPHIC_DEGRADED_FRACTION
```

The bundle is still written first (a catastrophic run's trajectories remain
inspectable), the degraded count joins the "wrote …" log line, and `main()`
returns `EXIT_CATASTROPHIC_INFRA` (3) when catastrophic. Semantics identical
to the CLI runner: strictly `>` 0.5; zero attempted journeys is NOT
catastrophic (an all-CLI corpus sharded to a GUI runner measures nothing by
design).

Docs: `hack/dogfood/local-harness.md` exit-code table and
`docs/dogfooding-value.md` §7 currently scope the exit-3 guarantee to the CLI
runner — both are updated to cover both runners.

### F2 — modality filtering, both directions

- `run_journeys.py::main()` filters `modality == "gui"` journeys out before
  sharding (the mirror image of `select_gui_journeys`, as a named helper
  `select_cli_journeys(journeys)` next to it for symmetry — kept in
  `run_journeys.py` since the GUI module imports from it, not vice versa).
  The shard log line reports the exclusion: `N of M journeys (K gui excluded)`.
- `dogfood.yml` `setup` job emits `has_cli` (it already computes `n_cli`),
  and the `dogfood` (CLI) job gets `if: needs.setup.outputs.has_cli == 'true'`
  — the exact pattern of the proven `has_gui` guard. Both swarm jobs are
  terminal in the job graph (no `needs:` on them), so skipping is safe. The
  artifact-prep jobs (kernel/initramfs/…) still run when both modalities are
  present or either one is; conditioning them on `has_cli || has_gui` is left
  out deliberately (YAGNI — an empty journey set is an authoring error the
  setup job already surfaces).

Sharding stays consistent: setup already sizes `cli_matrix` from `n_cli`, so
the runner-side filter makes the actual shard contents match the matrix that
was derived for them.

### F3 — `_eval_json` unwraps the agent-browser envelope

`driver.py::_eval_json` unwrap order becomes:

1. `doc["data"]["result"]` when `doc` is a dict with a dict `data` that has a
   `result` key (the real agent-browser `--json` envelope);
2. else `doc.get("result", doc)` when `doc` is a dict (legacy/bare wrapping,
   preserves current behavior for FakeDriver-adjacent shapes);
3. else the parsed value itself;
4. a string value still gets a second `json.loads` pass (unchanged — the
   envelope carries `JSON.stringify` output as a string).

This single fix restores `read_invoke_log()` **and** `read_console_errors()`
on real runs. Unit tests pin the real envelope verbatim (captured from the
probe) for both a JSON-string `result` and a raw-value `result`, plus the
legacy shapes.

### F4 — collector modality split

`collect-trajectories.py` gains an **additive**
`totals.by_kind_by_modality = {"cli": {kind: n}, "gui": {kind: n}}` (only
modalities that occur appear as keys). The flat `by_kind` stays — existing
consumers (skeptic prompt, summaries) keep working. The human-readable
summary print includes the split when both modalities are present. Tested via
the existing `_load_collector()` pattern in `hack/dogfood/test_runner.py`.

## 3. Testing

- `hack/dogfood/gui/test_run_gui_journeys.py`: exit-3 when >50% of GUI
  journeys are degraded (FakeModel error / `_wait_port` monkeypatched False,
  per the existing `test_sidecar_startup_failure_records_infra_candidate`
  conventions); exit 0 at exactly 50% (boundary pin, mirroring the CLI test);
  exit 0 for zero attempted journeys; bundle still written on exit 3.
- `hack/dogfood/test_runner.py`: CLI runner excludes `modality:"gui"` journeys
  from sharding; mixed-corpus shard contents match; collector
  `by_kind_by_modality` split.
- `hack/dogfood/gui/test_driver.py`: `_eval_json` fixtures for the real
  envelope (string + raw `result`), legacy top-level `result`, bare value,
  garbage; `read_invoke_log`/`read_console_errors` through the envelope.
- Workflow YAML: `has_cli` output asserted by inspection + the summary-table
  dry run (no YAML unit-test harness exists; the `setup` job's python is
  exercised in CI itself).
- Full gate: `python3 -m pytest hack/dogfood/ -q` green (was 158 passed).

## 4. Out of scope

Unchanged from the instrument-honesty spec §2: GUI Phase-3 deep work (headless
dispatch beyond 12/35 IPC commands, real `ui_daemon_diff` differential,
act→settle→snapshot, stateful marks), #116 cross-shard capability isolation,
push-triggered swarms. Also out: conditioning artifact-prep jobs on modality,
and any trajectory-schema change (`by_kind_by_modality` lives only in the
collector output).
