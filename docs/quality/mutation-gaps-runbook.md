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
   by reading its diff in the artifact, or by running cargo-mutants scoped to the
   file: `cargo mutants -f <file>`.
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
