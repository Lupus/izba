# Mutation Testing in CI — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Integrate `cargo-mutants` into izba CI as a blocking incremental gate on changed lines, plus a weekly sharded full run that publishes a machine-readable worklist (artifact + tracking issue) an LLM agent addresses iteratively via test-only PRs.

**Architecture:** A single committed `.cargo/mutants.toml` skip-list governs *what is mutable* for both pipelines (it applies in `--in-diff`, `--shard`, and full modes alike), structurally excluding KVM/VMM code that hosted-runner tests cannot kill. All non-trivial logic lives in testable `hack/` scripts (mirroring `hack/coverage.sh`); the workflow YAML (`.github/workflows/mutants.yml`) stays thin. One shared Python reporter (`hack/mutants-report.py`) renders both the gate step-summary and the full-run worklist, so the two pipelines never diverge.

**Tech Stack:** `cargo-mutants` 27.1.0, GitHub Actions (matrix sharding + artifacts), Python 3 (stdlib only) for the reporter, `gh` CLI for the tracking issue, bash for the thin wrappers.

## Global Constraints

These apply to **every** task below; copied verbatim from repo conventions and the spec.

- **Conventional commits**: `feat(ci): ...`, `docs(ci): ...`, `test(ci): ...`. TDD where the deliverable is code/script logic.
- **Pin every GitHub Action to a full commit SHA** with a `# vX.Y.Z` comment — match the SHAs already in `.github/workflows/`:
  - `actions/checkout@9f698171ed81b15d1823a05fc7211befd50c8ae0 # v6.0.3`
  - `Swatinem/rust-cache@23869a5bd66c73db3c0ac40331f3206eb23791dc # v2.9.1`
  - `taiki-e/install-action@7a79fe8c3a13344501c80d99cae481c1c9085912 # v2.81.10`
  - `actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1`
  - `actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1`
- **Weekly cron convention**: `0 3 * * 1` (Mon 03:00 UTC), as in `e2e.yml`.
- **`cargo-mutants` 27.1.0 verified facts** (do NOT re-derive — confirmed against the installed binary):
  - Config file default path: `.cargo/mutants.toml`. Keys are snake_case: `exclude_globs`, `exclude_re`, `examine_globs`, `timeout_multiplier`, `minimum_test_timeout`, `test_workspace`, `additional_cargo_test_args`. Config excludes apply in ALL modes including `--in-diff` and `--shard`.
  - `--shard K/N` is **1-indexed** (`1/8` … `8/8`), NOT 0-indexed. Default sharding method is round-robin (`--sharding round-robin`); mutant `i` runs on shard `i % N`.
  - `--in-diff <file>` takes a unified diff; it is line-precise for operator/value mutants and additionally includes a function's body-replacement mutant if any line of that function is in the diff.
  - Output: `<-o path>/mutants.out/` contains `missed.txt`, `caught.txt`, `timeout.txt`, `unviable.txt` (one mutant per line, format `path:line:col: description`), plus `outcomes.json`, `mutants.json`, and a `diff/` dir.
  - **Worklist source of truth is `missed.txt`** — one clean line per surviving mutant. The full `mutants.out/` is shipped as the machine-readable artifact.
  - Baseline: cargo-mutants runs the unmutated suite first; KVM tests self-skip (pass) on hosted runners, so the baseline is green there.
  - Mutant counts at time of writing (pre-exclude): izba-proto 29, izba-core 1269, izba-cli 240, izba-init 218, izba-ttytest 99 (~1855 total).
- **Toolchain in this repo**: scripts source `.cargo-env` if present (`[[ -f .cargo-env ]] && source .cargo-env`). In a worktree the toolchain lives in the main checkout under `.toolchain/`; CI installs normally.
- **Local verification of scripts** uses Python 3 (stdlib), `jq`, and `gh` — all available. `actionlint`/`shellcheck` are NOT preinstalled; install them in the task that needs them (download `actionlint` from its GitHub release; `shellcheck` via apt).

---

## File Structure

- Create: `.cargo/mutants.toml` — shared skip-list + timeouts (Task 1).
- Create: `hack/mutants-report.py` — shared reporter: merge `mutants.out` dirs → JSON worklist + markdown (gate mode and full mode) (Task 2).
- Create: `hack/mutants-report.test.py` — unit tests for the reporter, fixture-driven (Task 2).
- Create: `hack/mutants-gate.sh` — compute PR diff, run `cargo mutants --in-diff`, render summary, set exit code (Task 3).
- Create: `hack/mutants-issue.sh` — upsert the `mutation-gaps` tracking issue via `gh` (Task 5).
- Create: `.github/workflows/mutants.yml` — incremental gate job (PR) + sharded full-run matrix + collect job (schedule/dispatch) (Tasks 4 + 6).
- Create: `docs/quality/mutation-gaps-runbook.md` — the tests-only agent loop + the exact `/schedule` routine prompt (Task 7).
- Modify: `CONTRIBUTING.md` (or create if absent) — document `#[mutants::skip]` + justification escape hatch (Task 7).

---

## Task 1: Shared skip-list config (`.cargo/mutants.toml`)

**Files:**
- Create: `.cargo/mutants.toml`

**Interfaces:**
- Produces: a config consumed by every later `cargo mutants` invocation (gate, shards). No code symbols.

- [ ] **Step 1: Write the config**

```toml
# .cargo/mutants.toml — single source of truth for what cargo-mutants may mutate.
#
# cargo-mutants runs the HOST test suite against each mutant. Large parts of
# izba-core are KVM/VMM/real-VM code exercised ONLY by env-gated tests
# (IZBA_INTEGRATION=1) that SELF-SKIP on hosted CI runners. A mutant planted
# there can never be killed on a hosted runner — not because the tests are weak,
# but because the tests that would catch it never run. Excluding that code keeps
# BOTH the incremental PR gate and the scheduled full run honest (these globs
# apply in --in-diff and --shard modes too). Per-item exceptions use
# `#[mutants::skip]` WITH a justification comment (see CONTRIBUTING.md).
#
# This list is SEEDED from an initial local full run (see Task 8): every survivor
# is triaged into "untestable on host" (-> here / #[mutants::skip]) vs "real test
# gap" (-> left mutable, becomes the agent worklist).

exclude_globs = [
    "crates/izba-core/src/vmm/**",        # Cloud Hypervisor / OpenVMM drivers — need a real VM
    "crates/izba-core/tests/**",          # KVM-gated integration harness
    "crates/izba-cli/tests/**",           # daemon_e2e + tty e2e: KVM/PTY-gated
    "crates/izba-ttytest/**",             # drives a real binary through a PTY
    # NOTE: extend during Task 8 seeding with any other host-unkillable survivors.
]

# Give the suite headroom: some host tests spawn processes / do timed I/O.
timeout_multiplier = 3.0
minimum_test_timeout = 60
```

- [ ] **Step 2: Verify the config parses and excludes take effect**

Run (from repo root, toolchain on PATH):
```bash
cargo mutants --list -p izba-core 2>/dev/null | grep -c 'src/vmm/' ; echo "exit:$?"
```
Expected: `0` (no vmm mutants listed — the exclude glob removed them). If non-zero count, the glob is wrong; fix it.

- [ ] **Step 3: Verify a non-excluded package still lists mutants**

Run:
```bash
cargo mutants --list -p izba-proto 2>/dev/null | wc -l
```
Expected: `29` (unchanged — izba-proto is fully mutable).

- [ ] **Step 4: Commit**

```bash
git add .cargo/mutants.toml
git commit -m "feat(ci): add cargo-mutants skip-list config (.cargo/mutants.toml)"
```

---

## Task 2: Shared reporter (`hack/mutants-report.py`)

The one piece of real logic shared by both pipelines: read one or more `mutants.out` directories, merge + dedup surviving mutants, and emit (a) a JSON worklist and (b) a markdown rendering. Gate mode renders a step-summary and signals survivors via exit code; full mode renders the issue/worklist body.

**Files:**
- Create: `hack/mutants-report.py`
- Test: `hack/mutants-report.test.py`

**Interfaces:**
- Produces (CLI):
  - `python3 hack/mutants-report.py --mode gate   <out_dir> [<out_dir> ...]` → writes markdown to stdout; exit 1 if any survivor, else 0.
  - `python3 hack/mutants-report.py --mode full --json-out R.json --md-out W.md <out_dir> ...` → writes merged JSON + markdown files; always exit 0.
- Produces (Python API, used by tests):
  - `read_missed(out_dir: str) -> list[Mutant]` — parse `<out_dir>/missed.txt`.
  - `Mutant` = namedtuple `(path: str, line: int, col: int, desc: str, id_hash: str)`; `id_hash` = first 12 hex chars of sha256 of the raw missed.txt line.
  - `merge(dirs: list[str]) -> list[Mutant]` — union, dedup by `id_hash`, sorted by `(path, line, col)`.
  - `render_markdown(mutants: list[Mutant]) -> str` — checklist grouped by file.

- [ ] **Step 1: Write the failing tests**

```python
# hack/mutants-report.test.py
import os, tempfile, subprocess, sys, importlib.util, json

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("mr", os.path.join(HERE, "mutants-report.py"))
mr = importlib.util.module_from_spec(spec); spec.loader.exec_module(mr)

def _outdir(tmp, name, missed_lines):
    d = os.path.join(tmp, name, "mutants.out")
    os.makedirs(d)
    with open(os.path.join(d, "missed.txt"), "w") as f:
        f.write("\n".join(missed_lines) + ("\n" if missed_lines else ""))
    return d

def test_read_missed_parses_lines():
    with tempfile.TemporaryDirectory() as t:
        d = _outdir(t, "s1", ["crates/izba-proto/src/codec.rs:21:12: replace > with >= in write_frame"])
        got = mr.read_missed(d)
        assert len(got) == 1
        m = got[0]
        assert m.path == "crates/izba-proto/src/codec.rs"
        assert m.line == 21 and m.col == 12
        assert "replace > with >=" in m.desc
        assert len(m.id_hash) == 12

def test_merge_dedups_across_dirs_and_sorts():
    with tempfile.TemporaryDirectory() as t:
        line_a = "crates/izba-proto/src/codec.rs:21:12: replace > with >= in write_frame"
        line_b = "crates/izba-proto/src/dns.rs:35:36: replace | with ^ in servfail"
        d1 = _outdir(t, "s1", [line_a, line_b])
        d2 = _outdir(t, "s2", [line_a])          # duplicate of line_a
        merged = mr.merge([d1, d2])
        assert len(merged) == 2                   # deduped
        assert merged[0].path.endswith("codec.rs")  # sorted: codec before dns
        assert merged[1].path.endswith("dns.rs")

def test_render_markdown_groups_by_file_with_checkboxes():
    with tempfile.TemporaryDirectory() as t:
        d = _outdir(t, "s1", ["crates/izba-proto/src/codec.rs:21:12: replace > with >= in write_frame"])
        md = mr.render_markdown(mr.merge([d]))
        assert "crates/izba-proto/src/codec.rs" in md
        assert "- [ ]" in md
        assert "21:12" in md

def test_gate_mode_exit_1_on_survivors():
    with tempfile.TemporaryDirectory() as t:
        d = _outdir(t, "s1", ["crates/izba-proto/src/codec.rs:21:12: replace > with >= in write_frame"])
        r = subprocess.run([sys.executable, os.path.join(HERE, "mutants-report.py"),
                            "--mode", "gate", os.path.dirname(d)], capture_output=True, text=True)
        assert r.returncode == 1
        assert "codec.rs" in r.stdout

def test_gate_mode_exit_0_when_clean():
    with tempfile.TemporaryDirectory() as t:
        d = _outdir(t, "s1", [])   # no survivors
        r = subprocess.run([sys.executable, os.path.join(HERE, "mutants-report.py"),
                            "--mode", "gate", os.path.dirname(d)], capture_output=True, text=True)
        assert r.returncode == 0

def test_full_mode_writes_json_and_md():
    with tempfile.TemporaryDirectory() as t:
        d = _outdir(t, "s1", ["crates/izba-proto/src/dns.rs:35:36: replace | with ^ in servfail"])
        jp = os.path.join(t, "r.json"); wp = os.path.join(t, "w.md")
        r = subprocess.run([sys.executable, os.path.join(HERE, "mutants-report.py"),
                            "--mode", "full", "--json-out", jp, "--md-out", wp, os.path.dirname(d)],
                           capture_output=True, text=True)
        assert r.returncode == 0
        data = json.load(open(jp))
        assert data["survivors"][0]["path"].endswith("dns.rs")
        assert "id_hash" in data["survivors"][0]
        assert "dns.rs" in open(wp).read()

if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in fns:
        try:
            fn(); print(f"PASS {fn.__name__}")
        except Exception:
            failed += 1; print(f"FAIL {fn.__name__}"); traceback.print_exc()
    sys.exit(1 if failed else 0)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 hack/mutants-report.test.py`
Expected: FAIL — `mutants-report.py` does not exist yet (import error / file-not-found).

- [ ] **Step 3: Write the implementation**

```python
#!/usr/bin/env python3
# hack/mutants-report.py — merge cargo-mutants `missed.txt` survivors from one or
# more `mutants.out` directories into a JSON worklist + markdown checklist.
#
# Single source of truth for both CI pipelines:
#   --mode gate  : print a step-summary markdown to stdout; exit 1 if any survivor.
#   --mode full  : write merged JSON (--json-out) + markdown worklist (--md-out).
#
# Worklist source is `missed.txt` (one line per survivor: "path:line:col: desc").
import argparse, collections, hashlib, json, os, sys

Mutant = collections.namedtuple("Mutant", "path line col desc id_hash")


def _parse_line(raw):
    # Format: "crates/x/src/y.rs:21:12: replace > with >= in write_frame"
    raw = raw.rstrip("\n")
    if not raw.strip():
        return None
    head, _, desc = raw.partition(": ")
    parts = head.rsplit(":", 2)
    if len(parts) != 3:
        return None
    path, line, col = parts[0], parts[1], parts[2]
    try:
        line_i, col_i = int(line), int(col)
    except ValueError:
        return None
    id_hash = hashlib.sha256(raw.encode()).hexdigest()[:12]
    return Mutant(path, line_i, col_i, desc.strip(), id_hash)


def read_missed(out_dir):
    """Parse <out_dir>/missed.txt (out_dir is a `mutants.out` dir)."""
    fp = os.path.join(out_dir, "missed.txt")
    if not os.path.exists(fp):
        return []
    out = []
    with open(fp) as f:
        for raw in f:
            m = _parse_line(raw)
            if m:
                out.append(m)
    return out


def merge(dirs):
    seen, out = {}, []
    for d in dirs:
        for m in read_missed(d):
            if m.id_hash not in seen:
                seen[m.id_hash] = m
    out = list(seen.values())
    out.sort(key=lambda m: (m.path, m.line, m.col))
    return out


def render_markdown(mutants):
    if not mutants:
        return "No surviving mutants. 🎉\n"
    by_file = collections.OrderedDict()
    for m in mutants:
        by_file.setdefault(m.path, []).append(m)
    lines = [f"**{len(mutants)} surviving mutant(s)** across {len(by_file)} file(s).", ""]
    for path, ms in by_file.items():
        lines.append(f"### `{path}`")
        for m in ms:
            lines.append(f"- [ ] `{m.line}:{m.col}` {m.desc} <sub>`{m.id_hash}`</sub>")
        lines.append("")
    return "\n".join(lines)


def _mutant_to_dict(m):
    return {"path": m.path, "line": m.line, "col": m.col, "desc": m.desc, "id_hash": m.id_hash}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["gate", "full"], required=True)
    ap.add_argument("--json-out")
    ap.add_argument("--md-out")
    ap.add_argument("out_dirs", nargs="+", help="paths whose `mutants.out` subdir is read")
    args = ap.parse_args(argv)

    # Accept either a `mutants.out` dir directly or its parent.
    dirs = []
    for d in args.out_dirs:
        cand = d if os.path.basename(d) == "mutants.out" else os.path.join(d, "mutants.out")
        dirs.append(cand if os.path.isdir(cand) else d)

    mutants = merge(dirs)
    md = render_markdown(mutants)

    if args.mode == "gate":
        sys.stdout.write(md)
        return 1 if mutants else 0

    # full mode
    if args.json_out:
        with open(args.json_out, "w") as f:
            json.dump({"count": len(mutants), "survivors": [_mutant_to_dict(m) for m in mutants]}, f, indent=2)
    if args.md_out:
        with open(args.md_out, "w") as f:
            f.write(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 hack/mutants-report.test.py`
Expected: all `PASS`, exit 0.

- [ ] **Step 5: Commit**

```bash
git add hack/mutants-report.py hack/mutants-report.test.py
git commit -m "feat(ci): add shared cargo-mutants reporter (gate + full worklist)"
```

---

## Task 3: Incremental gate script (`hack/mutants-gate.sh`)

Computes the PR's merge-base diff, runs `cargo mutants --in-diff`, renders the survivor summary via the Task 2 reporter, and exits non-zero on any survivor. Keeping this in a script (not inline YAML) makes it locally runnable and reviewable.

**Files:**
- Create: `hack/mutants-gate.sh`

**Interfaces:**
- Consumes: `hack/mutants-report.py` (Task 2); `.cargo/mutants.toml` (Task 1).
- Produces (CLI): `hack/mutants-gate.sh <base_ref>` — writes a markdown summary to `$GITHUB_STEP_SUMMARY` (or stdout if unset); exit 1 on survivors or baseline failure.

- [ ] **Step 1: Write the script**

```bash
#!/usr/bin/env bash
# hack/mutants-gate.sh — incremental cargo-mutants gate for a PR.
#
# Runs cargo-mutants only on the lines changed vs the merge-base of <base_ref>.
# Any surviving (uncaught) mutant on changed lines fails the gate; the author
# must add a killing test or apply `#[mutants::skip]` with justification.
# Excludes from .cargo/mutants.toml apply here too, so a diff touching only
# KVM-only code generates zero mutants and passes trivially.
#
# Usage: hack/mutants-gate.sh <base_ref>   (e.g. hack/mutants-gate.sh origin/main)
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -f .cargo-env ]] && source .cargo-env

BASE_REF="${1:?usage: mutants-gate.sh <base_ref>}"
OUT="$(mktemp -d)"
SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/stdout}"

# 3-dot diff = changes since the merge-base (what the PR actually introduces).
git diff "${BASE_REF}...HEAD" > "$OUT/pr.diff"

if [[ ! -s "$OUT/pr.diff" ]]; then
  echo "## Mutation gate: no diff vs ${BASE_REF} — skipped" >> "$SUMMARY"
  exit 0
fi

# Run the gate. cargo-mutants exits non-zero if mutants survive OR on a baseline
# failure; capture its code to distinguish the two below.
set +e
cargo mutants --in-diff "$OUT/pr.diff" -o "$OUT/run" 2> "$OUT/stderr"
RC=$?
set -e

if [[ ! -d "$OUT/run/mutants.out" ]]; then
  # cargo-mutants never reached the testing phase -> baseline/build failure.
  {
    echo "## ⚠️ Mutation gate: baseline failure (not a survivor failure)"
    echo '```'
    tail -40 "$OUT/stderr"
    echo '```'
  } >> "$SUMMARY"
  exit 1
fi

# Render survivors (exit 1 if any) via the shared reporter.
{
  echo "## Mutation gate (incremental, vs ${BASE_REF})"
  echo
} >> "$SUMMARY"
set +e
python3 hack/mutants-report.py --mode gate "$OUT/run/mutants.out" >> "$SUMMARY"
GATE_RC=$?
set -e

if [[ $GATE_RC -ne 0 ]]; then
  {
    echo
    echo "❌ Surviving mutants on changed lines. Add a killing test, or apply"
    echo '`#[mutants::skip]` with a justification comment (see CONTRIBUTING.md).'
  } >> "$SUMMARY"
fi
exit $GATE_RC
```

- [ ] **Step 2: Make it executable and shellcheck it**

```bash
chmod +x hack/mutants-gate.sh
# install shellcheck if missing:
command -v shellcheck >/dev/null || sudo apt-get install -y shellcheck
shellcheck hack/mutants-gate.sh
```
Expected: no warnings (fix any reported).

- [ ] **Step 3: Smoke-test the no-diff path locally**

Run (against current HEAD, so the diff is empty):
```bash
GITHUB_STEP_SUMMARY=/dev/stdout hack/mutants-gate.sh HEAD
```
Expected: prints "no diff … skipped", exit 0.

- [ ] **Step 4: Smoke-test the survivor path locally**

```bash
# introduce a deliberately-untested change on a mutable line, then run the gate
sed -i 's/fn servfail/fn servfail \/* gate-test *\//' crates/izba-proto/src/dns.rs 2>/dev/null || true
# (pick any currently-mutable function with a known survivor; dns.rs:servfail has one)
GITHUB_STEP_SUMMARY=/dev/stdout hack/mutants-gate.sh HEAD~0 || echo "exit=$?"
git checkout -- crates/izba-proto/src/dns.rs
```
Expected: when the diff touches a function with an uncaught mutant, the summary lists it and exit is 1. (If the chosen change yields no survivor, that is also a valid pass — the point is verifying the script runs end-to-end and the reporter is wired.)

- [ ] **Step 5: Commit**

```bash
git add hack/mutants-gate.sh
git commit -m "feat(ci): add incremental cargo-mutants gate script"
```

---

## Task 4: Workflow — incremental gate job (`mutants.yml`, PR trigger)

**Files:**
- Create: `.github/workflows/mutants.yml`

**Interfaces:**
- Consumes: `hack/mutants-gate.sh` (Task 3).
- Produces: a required PR check named `mutation gate (incremental)`.

- [ ] **Step 1: Write the workflow (gate job only for now)**

```yaml
name: Mutants

on:
  pull_request:
  schedule:
    - cron: '0 3 * * 1'   # weekly full run, Mon 03:00 UTC (matches e2e.yml)
  workflow_dispatch:

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

permissions:
  contents: read

jobs:
  incremental:
    name: mutation gate (incremental)
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    timeout-minutes: 45
    steps:
      - uses: actions/checkout@9f698171ed81b15d1823a05fc7211befd50c8ae0 # v6.0.3
        with:
          fetch-depth: 0   # need the base branch to compute the merge-base diff
      - uses: Swatinem/rust-cache@23869a5bd66c73db3c0ac40331f3206eb23791dc # v2.9.1
        with:
          prefix-key: mutants-incremental
      - name: Install cargo-mutants
        uses: taiki-e/install-action@7a79fe8c3a13344501c80d99cae481c1c9085912 # v2.81.10
        with:
          tool: cargo-mutants
      - name: Fetch base ref
        run: git fetch --no-tags --depth=0 origin "${{ github.base_ref }}"
      - name: Incremental mutation gate
        run: hack/mutants-gate.sh "origin/${{ github.base_ref }}"
```

- [ ] **Step 2: Validate the workflow with actionlint**

```bash
# install actionlint if missing (download the release binary)
command -v actionlint >/dev/null || {
  bash <(curl -sSfL https://raw.githubusercontent.com/rhysd/actionlint/main/scripts/download-actionlint.bash)
  export PATH="$PWD:$PATH"
}
actionlint .github/workflows/mutants.yml
```
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/mutants.yml
git commit -m "feat(ci): add mutants.yml incremental PR gate"
```

---

## Task 5: Tracking-issue upsert script (`hack/mutants-issue.sh`)

**Files:**
- Create: `hack/mutants-issue.sh`

**Interfaces:**
- Consumes: a markdown body file (produced by `hack/mutants-report.py --mode full --md-out`).
- Produces (CLI): `hack/mutants-issue.sh <body-file>` — upserts the single open issue labeled `mutation-gaps`. Requires `gh` authenticated (`GH_TOKEN`/`GITHUB_TOKEN` with `issues: write`).

- [ ] **Step 1: Write the script**

```bash
#!/usr/bin/env bash
# hack/mutants-issue.sh — upsert the single "mutation-gaps" tracking issue.
#
# The body is regenerated from ground truth each run (currently-surviving
# mutants only); killed mutants simply disappear next run. No checkmark state to
# reconcile. Requires `gh` authenticated with issues:write.
#
# Usage: hack/mutants-issue.sh <body-file>
set -euo pipefail
BODY_FILE="${1:?usage: mutants-issue.sh <body-file>}"
LABEL="mutation-gaps"
TITLE="Mutation testing gaps (surviving mutants)"

# Ensure the label exists (idempotent).
gh label create "$LABEL" --color B60205 --description "cargo-mutants survivors worklist" 2>/dev/null || true

# Prepend a generated-by header so readers know it is auto-maintained.
HEADER="_Auto-generated by the weekly mutation run (\`.github/workflows/mutants.yml\`). Regenerated from ground truth each run — do not edit by hand. See \`docs/quality/mutation-gaps-runbook.md\`._\n\n"
TMP="$(mktemp)"
printf "%b" "$HEADER" > "$TMP"
cat "$BODY_FILE" >> "$TMP"

EXISTING="$(gh issue list --label "$LABEL" --state open --json number --jq '.[0].number' || true)"
if [[ -n "${EXISTING:-}" && "$EXISTING" != "null" ]]; then
  gh issue edit "$EXISTING" --body-file "$TMP"
  echo "Updated issue #$EXISTING"
else
  gh issue create --title "$TITLE" --label "$LABEL" --body-file "$TMP"
  echo "Created tracking issue"
fi
```

- [ ] **Step 2: shellcheck**

```bash
chmod +x hack/mutants-issue.sh
shellcheck hack/mutants-issue.sh
```
Expected: no warnings.

- [ ] **Step 3: Dry-run the body assembly (no gh calls)**

```bash
printf 'crates/x/src/y.rs:1:1: replace + with -\n' > /tmp/missed.txt
mkdir -p /tmp/s1/mutants.out && cp /tmp/missed.txt /tmp/s1/mutants.out/missed.txt
python3 hack/mutants-report.py --mode full --md-out /tmp/body.md --json-out /tmp/r.json /tmp/s1
cat /tmp/body.md
```
Expected: a grouped markdown checklist (verifies the reporter→issue handoff format). The `gh` path itself is exercised in CI (Task 6), not locally.

- [ ] **Step 4: Commit**

```bash
git add hack/mutants-issue.sh
git commit -m "feat(ci): add mutation-gaps tracking-issue upsert script"
```

---

## Task 6: Workflow — sharded full run + collect job

Adds the scheduled/dispatch jobs to `mutants.yml`: a sharded matrix that runs the full mutation suite and uploads per-shard `mutants.out`, then a collect job that merges them into the report artifact and upserts the tracking issue.

**Files:**
- Modify: `.github/workflows/mutants.yml` (append two jobs; widen `permissions`).

**Interfaces:**
- Consumes: `hack/mutants-report.py` (Task 2), `hack/mutants-issue.sh` (Task 5).
- Produces: artifact `mutants-report` (JSON + markdown) and the upserted `mutation-gaps` issue.

- [ ] **Step 1: Widen permissions for the issue write**

Change the top-level `permissions:` block in `mutants.yml` to:

```yaml
permissions:
  contents: read
  issues: write   # collect job upserts the mutation-gaps tracking issue
```

- [ ] **Step 2: Append the sharded full-run job**

```yaml
  full-shard:
    name: full mutation run (shard ${{ matrix.shard }}/8)
    if: github.event_name != 'pull_request'
    runs-on: ubuntu-latest
    timeout-minutes: 120
    strategy:
      fail-fast: false
      matrix:
        shard: [1, 2, 3, 4, 5, 6, 7, 8]
    steps:
      - uses: actions/checkout@9f698171ed81b15d1823a05fc7211befd50c8ae0 # v6.0.3
      - uses: Swatinem/rust-cache@23869a5bd66c73db3c0ac40331f3206eb23791dc # v2.9.1
        with:
          prefix-key: mutants-full
      - name: Install cargo-mutants
        uses: taiki-e/install-action@7a79fe8c3a13344501c80d99cae481c1c9085912 # v2.81.10
        with:
          tool: cargo-mutants
      - name: Run shard (non-zero exit on survivors is expected; do not fail)
        run: cargo mutants --shard ${{ matrix.shard }}/8 -o shard-out || true
      - name: Upload shard results
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: mutants-shard-${{ matrix.shard }}
          path: shard-out/mutants.out
          if-no-files-found: warn
```

- [ ] **Step 3: Append the collect job**

```yaml
  collect:
    name: collect + publish worklist
    if: github.event_name != 'pull_request'
    needs: full-shard
    runs-on: ubuntu-latest
    timeout-minutes: 15
    env:
      GH_TOKEN: ${{ github.token }}
    steps:
      - uses: actions/checkout@9f698171ed81b15d1823a05fc7211befd50c8ae0 # v6.0.3
      - name: Download all shard results
        uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        with:
          pattern: mutants-shard-*
          path: shards
      - name: Merge shards into report
        run: |
          python3 hack/mutants-report.py --mode full \
            --json-out mutants-report.json --md-out mutants-report.md \
            shards/mutants-shard-*
          cat mutants-report.md >> "$GITHUB_STEP_SUMMARY"
      - name: Upload merged report
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: mutants-report
          path: |
            mutants-report.json
            mutants-report.md
          if-no-files-found: warn
      - name: Upsert tracking issue
        run: hack/mutants-issue.sh mutants-report.md
```

> Note on `download-artifact` paths: with `pattern: mutants-shard-*` and `path: shards`, each artifact lands in `shards/mutants-shard-<n>/` containing the `mutants.out` contents (we uploaded `path: shard-out/mutants.out`, so the artifact root **is** the `mutants.out` contents). `hack/mutants-report.py` accepts either a `mutants.out` dir or its parent and falls back to the given dir if no `mutants.out` child exists — so `shards/mutants-shard-*` resolves correctly. Verify in Step 5.

- [ ] **Step 4: actionlint the full workflow**

```bash
actionlint .github/workflows/mutants.yml
```
Expected: no errors.

- [ ] **Step 5: Verify the collect path-resolution locally with synthetic shard dirs**

```bash
rm -rf /tmp/shards && mkdir -p /tmp/shards/mutants-shard-1 /tmp/shards/mutants-shard-2
printf 'crates/a/src/x.rs:10:5: replace + with -\n' > /tmp/shards/mutants-shard-1/missed.txt
printf 'crates/b/src/y.rs:20:5: replace * with +\n' > /tmp/shards/mutants-shard-2/missed.txt
python3 hack/mutants-report.py --mode full --json-out /tmp/r.json --md-out /tmp/r.md /tmp/shards/mutants-shard-*
jq '.count' /tmp/r.json   # expect 2
```
Expected: `2` — confirms the artifact layout (`mutants.out` contents at the artifact root) is parsed correctly by the reporter's dir fallback.

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/mutants.yml
git commit -m "feat(ci): add sharded full mutation run + worklist collect job"
```

---

## Task 7: Agent runbook + contributing-guide escape hatch

**Files:**
- Create: `docs/quality/mutation-gaps-runbook.md`
- Modify: `CONTRIBUTING.md` (create if absent)

**Interfaces:** none (documentation).

- [ ] **Step 1: Write the runbook**

```markdown
# Mutation gaps — agent runbook

The weekly mutation run (`.github/workflows/mutants.yml`) publishes:
- a **tracking issue** labeled `mutation-gaps` (the worklist), and
- a **`mutants-report` artifact** (`mutants-report.json` for detail).

This runbook is the tests-only loop for closing those gaps.

## The loop

1. Read the open `mutation-gaps` issue; pull `mutants-report.json` from the latest
   `Mutants` workflow run (`gh run download -n mutants-report`).
2. Dedup against open PRs labeled `mutation-gaps` — skip mutants a still-open PR
   already targets (match by `id_hash`).
3. Pick a batch (default cap: 10 mutants per PR run).
4. For each mutant, write a **killing test** (TDD): confirm it FAILS against the
   mutation's intent and PASSES against the real code. Reproduce a mutant locally
   with `cargo mutants -f <file> --line-in-diff <n>` or by reading its diff in the
   artifact.
5. Run the six workspace gates before proposing: `cargo fmt --check`,
   `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`,
   `cargo build -p izba-init --target x86_64-unknown-linux-musl --release`,
   `cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli`,
   `cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings`.
6. Open ONE PR per batch, labeled `mutation-gaps`, listing the `id_hash`es it
   addresses. The incremental gate validates the PR; the next weekly run drops the
   closed gaps from the issue automatically.

## Hard guardrail

The agent **only adds tests** (and, with a written justification comment,
`#[mutants::skip]`). It must **never** alter production logic to make a mutant
unviable or to satisfy the suite. If a survivor is genuinely untestable on the
host (KVM/VMM/platform glue), add it to `.cargo/mutants.toml` `exclude_globs` or
annotate with `#[mutants::skip]` + justification — never paper over it.

## Scheduled cloud routine (`/schedule`)

Create a routine that fires a few days after the weekly run (e.g. Thursday 09:00),
with this prompt:

> Read the open GitHub issue labeled `mutation-gaps` in this repo. Follow
> `docs/quality/mutation-gaps-runbook.md` exactly: pick up to 10 surviving mutants
> not already targeted by an open `mutation-gaps` PR, write a killing test for each
> (tests only — never change production logic), run all six workspace gates, and
> open one PR labeled `mutation-gaps` listing the id_hashes addressed. If the issue
> is empty or all items already have open PRs, do nothing and report that.
```

- [ ] **Step 2: Add the escape-hatch note to CONTRIBUTING.md**

Append (or create the file with) this section:

```markdown
## Mutation testing (cargo-mutants)

CI runs `cargo-mutants`: the incremental PR gate fails if any mutant on your
changed lines survives (no test notices the change). To fix, add a test that
would catch the mutation. If a line is genuinely not worth a test (trivial glue,
host-unkillable VMM code), annotate it and **always explain why**:

    #[mutants::skip] // reason: <one line — why this mutant is not worth a test>

Host-unkillable subsystems (KVM/VMM/real-VM paths) are excluded wholesale in
`.cargo/mutants.toml`; extend those globs rather than scattering skips.
```

- [ ] **Step 3: Commit**

```bash
git add docs/quality/mutation-gaps-runbook.md CONTRIBUTING.md
git commit -m "docs(ci): mutation-gaps agent runbook + cargo-mutants escape hatch"
```

---

## Task 8: Seed the skip-list from a real full run (gate-readiness)

This is the step that makes the gate trustworthy: run the full suite once, triage
every survivor, and either exclude host-unkillable ones or note the real gaps.
This task produces commits to `.cargo/mutants.toml` (excludes) and a short
triage note; it does NOT try to fix gaps (that is the agent loop's job).

**Files:**
- Modify: `.cargo/mutants.toml` (extend `exclude_globs` / note `#[mutants::skip]` sites)
- Create: `docs/quality/mutation-baseline.md` (triage summary)

- [ ] **Step 1: Run a full mutation pass (long-running; can shard locally)**

```bash
cargo mutants -o target/mutants-seed 2>&1 | tail -5
# or, to parallelize locally, run shards 1/4..4/4 into separate dirs and merge.
```
Expected: completes; `target/mutants-seed/mutants.out/missed.txt` lists all survivors.

- [ ] **Step 2: Triage survivors into two buckets**

```bash
python3 hack/mutants-report.py --mode full \
  --json-out target/seed.json --md-out target/seed.md target/mutants-seed
sed 's#:.*##' target/mutants-seed/mutants.out/missed.txt | sort | uniq -c | sort -rn
```
For each surviving file, decide: **host-unkillable** (KVM/VMM/platform glue, or
only reachable by env-gated tests) → add to `exclude_globs` or `#[mutants::skip]`
with justification; **real test gap** → leave mutable (becomes the agent worklist).

- [ ] **Step 3: Apply excludes and re-run to confirm a clean classification**

Edit `.cargo/mutants.toml` per the triage, then:
```bash
cargo mutants --list 2>/dev/null | sed 's#:.*##' | sort -u
```
Expected: only genuinely host-testable files remain in the mutable set.

- [ ] **Step 4: Write the triage summary**

Create `docs/quality/mutation-baseline.md` recording: total mutants, excluded
globs added (with the one-line reason each), and the count of real gaps remaining
(the initial agent worklist size).

- [ ] **Step 5: Commit**

```bash
git add .cargo/mutants.toml docs/quality/mutation-baseline.md
git commit -m "feat(ci): seed cargo-mutants skip-list from initial full run"
```

---

## Task 9: Wire branch protection + create the cloud routine (handoff)

These two actions are not code — they are repo/account settings done by the owner
(or the agent with the right tokens). Listed so they are not forgotten.

- [ ] **Step 1: Make the incremental gate a required check**

After the first PR run of `mutants.yml` reports the check `mutation gate
(incremental)`, add it to `main` branch protection's required status checks
(GitHub Settings → Branches, or `gh api`).

- [ ] **Step 2: Create the `/schedule` cloud routine**

Using the prompt in `docs/quality/mutation-gaps-runbook.md` (§ Scheduled cloud
routine), create the routine to fire a few days after the weekly run.

- [ ] **Step 3: First-run validation**

Trigger the full run manually (`gh workflow run mutants.yml`), confirm the
`mutants-report` artifact is produced and the `mutation-gaps` issue is created.

---

## Self-Review

- **Spec coverage:**
  - §1 shared skip-list → Task 1 (+ Task 8 seeding). ✓
  - §2 incremental gate (zero survivors + `#[mutants::skip]`) → Task 3 (script) + Task 4 (workflow) + Task 7 (escape hatch doc). ✓
  - §3 sharded full run + collect + artifact + tracking issue (regenerate from ground truth) → Task 2 (reporter), Task 5 (issue upsert), Task 6 (workflow). ✓
  - §4 agent loop (runbook + `/schedule`, tests-only guardrail) → Task 7 + Task 9. ✓
  - §5 risks (timeouts, baseline flakiness, false blocks, scope creep) → addressed in Task 1 (timeouts/excludes), Task 3 (baseline-vs-survivor distinction), Task 7 (tests-only guardrail). ✓
  - §6 deliverables → Tasks 1–9 enumerate all six. ✓
- **Placeholder scan:** all code/scripts are complete; no TBD/TODO. The only deliberately-open content is the *contents* of the seeded excludes (Task 8), which can only be determined by running the real suite — the task gives the exact procedure. ✓
- **Type/name consistency:** `Mutant` namedtuple fields, `read_missed`/`merge`/`render_markdown` signatures, `--mode gate|full`, `--json-out`/`--md-out`, and the `id_hash` (12-hex sha256) are used identically across Tasks 2, 3, 5, 6. The label `mutation-gaps` and artifact name `mutants-report` are consistent across Tasks 5, 6, 7, 9. ✓
