# izba code-coverage metrics & QA gap report — design

Date: 2026-06-14
Status: approved-pending-implementation (Phase 1)

## Goal

Introduce code-coverage measurement across izba's CI test suites and produce an
**actionable, QA-facing report** that ranks where coverage is weakest so a QA
specialist can decide where to add tests. Coverage spans the Rust workspace
(`izba-proto`/`izba-core`/`izba-cli`/`izba-init`) today and is designed to
extend to the real-VM e2e host paths and the Tauri desktop app (`app/` frontend
+ `app/src-tauri` backend) in later phases.

Coverage is **report-only**: it establishes a baseline and a gap report. It does
NOT gate CI on a threshold (that can be ratcheted in later once a baseline
exists).

## Decisions (locked during brainstorming)

| Decision | Choice | Rationale |
| --- | --- | --- |
| Rust coverage tool | `cargo-llvm-cov` | Source-based LLVM coverage; accurate region/line/function data; JSON + lcov + HTML; instruments subprocesses via `show-env` (needed for the daemon/CLI binaries e2e spawns). |
| Frontend tool | `vitest run --coverage` + `@vitest/coverage-v8` | Already on vitest; v8 provider needs no extra transform. (Phase 3.) |
| Reporting | Self-contained | HTML + lcov as CI artifacts, gap report in `$GITHUB_STEP_SUMMARY` and as a committed/artifact markdown file. No third-party service, nothing uploaded externally. |
| Enforcement | Report-only | Baseline first; no threshold gate. |
| Gap-report tool | Python (`hack/coverage_report.py`) | `python3` is present on GH runners and WSL; clean JSON parsing + markdown formatting. |
| e2e host-side | Included (Phase 2) | Capture host paths only the real microVM tests exercise. |
| App coverage | Coverage-only, Phase 3 | Coordinate with the in-flight `feat/izba-app-ci-packaging` branch (`app.yml`). |

## Phasing

This spec is implemented in three phases. **Phase 1 is the deliverable for this
worktree**; Phases 2 and 3 are designed here but implemented after review.

1. **Phase 1 — core Rust workspace coverage (this worktree).**
   `cargo-llvm-cov` over the host unit + integration suite, `hack/coverage.sh`
   + `hack/coverage_report.py`, a new `coverage.yml` workflow (`rust-host` +
   `report` jobs), the `coverage-gaps.md` report, and docs.
2. **Phase 2 — real-VM e2e host-side coverage (BUILT).** Separate
   `linux-kvm-coverage` + `windows-whp-coverage` jobs in `e2e.yml` (weekly cron
   + dispatch, isolated from the gates) run the host + gated suites under one
   instrumented shell each. Linux emits a merged host+e2e report (validated
   locally against real KVM); Windows emits its own platform report (real
   OpenVMM/WHP driver paths), not cross-merged.
3. **Phase 3 — Tauri app coverage.** Frontend `vitest --coverage` + `src-tauri`
   `cargo-llvm-cov`, plugged into `app.yml`.

## Components

### 1. `hack/coverage.sh` — local + CI entry point

A single script that mirrors what CI does, usable locally:

```
hack/coverage.sh [--html] [--open] [--no-report]
```

Behavior:
- Sources `.cargo-env` if present (sandbox-local toolchain convention).
- Verifies `cargo-llvm-cov` is installed; if not, prints the exact
  `cargo install cargo-llvm-cov` / `rustup component add llvm-tools-preview`
  hint and exits non-zero (does NOT auto-install).
- Runs `cargo llvm-cov --workspace --lcov --output-path target/coverage/lcov.info`
  and `cargo llvm-cov report --json --output-path target/coverage/coverage.json`
  (reusing the same profile data — `--no-report` on the test run, then two
  `report` invocations, to avoid recompiling/re-running tests per format).
- With `--html`, also emits `target/coverage/html`.
- Invokes `hack/coverage_report.py target/coverage/coverage.json` to write
  `target/coverage/coverage-gaps.md`.
- Honors `IZBA_INTEGRATION` passthrough: when set, the KVM-gated integration
  tests run and contribute coverage (otherwise they self-skip, same as
  `cargo test`).

Default output dir: `target/coverage/` (git-ignored).

### 2. `hack/coverage_report.py` — the QA gap report

Pure-stdlib Python 3 (no pip deps). Input: the `cargo llvm-cov report --json`
file. Output: markdown to stdout or `--out <path>`.

The llvm-cov JSON has `data[0].files[]` with per-file `summary.lines`,
`.functions`, `.regions` (each `{count, covered, percent}`), and
`data[0].totals`. The script produces:

1. **Headline** — overall line / function / region coverage %, and total
   covered/total lines.
2. **Per-crate table** — files grouped by crate (derived from the path prefix
   `crates/<name>/`), each crate's aggregate line %, sorted ascending (worst
   first).
3. **Coverage gaps** — a table of individual files sorted by **uncovered line
   count descending** (most missing lines = highest test-writing impact),
   showing `file | line% | uncovered lines | uncovered functions`. Top N
   (default 25, `--top` configurable).
4. **Zero-coverage callout** — a separate list of files with 0% line coverage
   (often whole modules with no tests at all), since these are the clearest QA
   targets.

The report header states explicitly that it ranks by *uncovered-line impact*,
not by percentage, so a small fully-uncovered file does not outrank a large
half-covered one.

Test paths (`tests/`, `#[cfg(test)]` modules) and generated/vendored code are
excluded from the gap ranking via llvm-cov's own `--ignore-filename-regex`
(configured in `coverage.sh`), so the report focuses on production code.

### 3. `coverage.yml` — CI workflow (new, report-only)

Triggers: `pull_request` + `push` to `main` (matches `ci.yml`). Concurrency
group cancels in-progress. `permissions: contents: read`.

Jobs:

- **`rust-host`** (`ubuntu-latest`, ~30 min): checkout → `rust-cache` (own
  `prefix-key: coverage`) → `rustup component add llvm-tools-preview` +
  `cargo install cargo-llvm-cov` (or the
  `taiki-e/install-action@cargo-llvm-cov` pinned action, sha-pinned to match the
  repo's pinned-action convention) → `hack/coverage.sh --html`. Uploads
  `target/coverage/{lcov.info,html,coverage-gaps.md}` as an artifact and writes
  `coverage-gaps.md` to `$GITHUB_STEP_SUMMARY`. This job's number is the
  canonical headline.

In Phase 1 there is a single coverage input, so `rust-host` itself uploads the
`coverage-report` artifact (lcov + json + html + gap report) and writes the gap
report to `$GITHUB_STEP_SUMMARY` — a separate `report` job would only re-download
and re-upload one input (YAGNI). Phase 2 introduces a dedicated `report` job that
merges the e2e Linux lcov with `lcov-host.info` before generating the unified
report.

No threshold/failure step. The workflow's value is the artifacts + summary.

### 4. Phase 2 — e2e host-side coverage (BUILT)

The real-VM tests in `e2e.yml` exercise host-side `izba-core` paths (VMM driver,
vsock bridging, daemon splice) that the fast host suite cannot reach. Phase 2
adds a **separate `linux-kvm-coverage` job** to `e2e.yml`:

- **Isolated from the gate.** The existing `linux-kvm` job stays the
  authoritative real-VM test gate, untouched. A coverage-instrumentation problem
  can never break it. The coverage job is `if: github.event_name != 'push'` —
  it runs on the weekly cron + manual dispatch only, so it does not double the
  expensive real-VM minutes on every main push.
- **Self-contained merge, no cross-workflow lcov merge.** The job runs the host
  workspace suite *and* the gated real-VM suites (`integration`, `daemon_e2e`)
  under a single `source <(cargo llvm-cov show-env --export-prefix)` shell, so
  every cargo invocation is instrumented and all profraw accumulate into one
  profile set. A single `cargo llvm-cov report` then yields a genuine host+e2e
  **merge** in one artifact — avoiding the fragile cross-workflow lcov merge
  (control-char `RUSTFLAGS`, `$GITHUB_ENV` quoting) the multi-step variant would
  require. The spawned `izba`/`izbad` binaries inherit `LLVM_PROFILE_FILE` and
  emit their own profraw, so subprocess host paths are captured too. **Validated
  locally against real KVM** before landing (a single boot test alone covered
  19.3% of izba-core; `daemon_e2e` confirmed subprocess capture).
- Report-only: suites run under `set +e` so a flake cannot wipe the report; the
  gap report (`coverage-gaps-e2e.md`), lcov, json, and HTML upload as the
  `coverage-report-e2e` artifact + step summary (all `if: always()`).
- **Windows** (WHP) gets a parallel `windows-whp-coverage` job, same posture
  (separate from the windows-whp gate, non-push gated). A single bash step
  sources show-env, runs the Windows host suite + builds the instrumented
  `izba.exe`, then invokes the pwsh validation suite as a child — so the
  spawned `izba.exe` inherits `LLVM_PROFILE_FILE` and the real OpenVMM/WHP
  driver host paths (`vmm/openvmm.rs` + Windows-only code) are captured. It is
  reported as its **own** platform artifact (`coverage-report-e2e-windows`),
  NOT merged with the Linux reports: the code paths differ and the
  absolute/backslash paths would not align, so a cross-platform merge would
  corrupt the report. The ignore-regex is separator-agnostic
  (`[\\/]tests[\\/]`…) so it matches Windows backslash paths. Unlike the KVM
  leg this was not validated locally (Windows coverage needs WHP + OpenVMM); it
  mirrors the KVM-validated single-shell pattern and is report-only + isolated,
  so a first-run issue surfaces on the weekly run without touching any gate.
- **Guest-side** `izba-init` running *inside* the microVM is not capturable; its
  host-testable modules are already covered by the host suite.

### 5. Phase 3 — Tauri app coverage (designed, not built this pass)

Coordinated with `feat/izba-app-ci-packaging`'s `app.yml`:

- **Frontend:** add `@vitest/coverage-v8` devDep; a `test:coverage` npm script
  (`vitest run --coverage`) producing lcov + HTML; wire `--coverage` into the
  app CI frontend test step and upload the artifact.
- **Backend (`app/src-tauri`):** `cargo llvm-cov` run with its own manifest
  (the crate is excluded from the workspace), producing its own lcov + the gap
  report appended.
- Both feed the same `coverage_report.py` (frontend lcov is converted/handled,
  or reported in its own section) so QA sees one consolidated picture.

## Data flow

```
cargo test (instrumented)  ─┐
                            ├─► profraw ─► cargo llvm-cov report ─► coverage.json ─► coverage_report.py ─► coverage-gaps.md
real-VM e2e (Phase 2)      ─┘                                  └─► lcov.info ──────────────────────────► merge (Phase 2)
                                                               └─► html/ ─────────────────────────────► CI artifact + step summary
```

## Error handling

- `coverage.sh` fails fast with an install hint if `cargo-llvm-cov` is missing
  (never auto-installs in a dev checkout).
- `coverage_report.py` fails with a clear message if the JSON is missing or
  malformed (e.g. an empty/failed coverage run), rather than emitting a
  misleading empty report.
- CI coverage jobs do not fail the build on low coverage (report-only). Tests
  run under `--no-fail-fast` so a single failing/flaky test cannot abort the run
  and wipe the report: the report is always generated and uploaded (the
  workflow's summary + upload steps use `if: always()`). `coverage.sh` then
  exits with the test status so a genuine failure still shows red, while
  CI's `linux-gates` job remains the authoritative test gate. A compilation
  failure (no profile data) aborts naturally — there is nothing to report.

## Testing

- `coverage_report.py` gets unit tests (`hack/test_coverage_report.py`,
  stdlib `unittest`) against a small fixture llvm-cov JSON, asserting: headline
  math, per-crate grouping, gap ordering (by uncovered-line count desc), and the
  zero-coverage callout. Run via `python3 -m unittest` — added to the `coverage`
  workflow as a quick step.
- `coverage.sh` is validated by running it locally against the real workspace
  (`IZBA_INTEGRATION` unset) and confirming it produces a non-empty
  `coverage-gaps.md` and HTML.
- The existing six CLAUDE.md gates remain green (the new files are scripts +
  workflow + docs; no Rust source changes in Phase 1).

## Out of scope (this spec)

- Threshold/gate enforcement (future ratchet).
- Guest-side (`izba-init` musl PID1 running *inside* the microVM) runtime
  coverage — not capturable without in-guest instrumentation infra; its
  host-testable modules are still covered by the host suite.
- Historical trend tracking / badges (would need an external service or a
  committed-history mechanism; deferred).

## Files touched (Phase 1)

- `hack/coverage.sh` (new)
- `hack/coverage_report.py` (new)
- `hack/test_coverage_report.py` (new)
- `.github/workflows/coverage.yml` (new)
- `.gitignore` (+`target/coverage/` if not already covered by `target/`)
- `docs/testing.md` (+ coverage runbook section)
- `CLAUDE.md` (+ coverage command in Build & test)

## Files touched (Phase 2)

- `.github/workflows/e2e.yml` (+ `linux-kvm-coverage` and `windows-whp-coverage`
  jobs; separator-agnostic ignore-regex)
- `docs/testing.md` + `CLAUDE.md` (real-VM coverage notes)
- reuses `hack/coverage_report.py` unchanged (`--title` flag)
