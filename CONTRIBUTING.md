# Contributing to izba

See [CLAUDE.md](CLAUDE.md) for the build/test gates and architecture, and
[docs/](docs/) for design specs. This file collects contributor-facing rules
that do not belong in the build docs.

## Mutation testing (cargo-mutants)

CI runs [`cargo-mutants`](https://mutants.rs): the incremental PR gate
(`.github/workflows/mutants.yml`) fails if any mutant on your changed lines
survives — i.e. no test notices when cargo-mutants alters that code. To fix,
add a test that would catch the mutation.

The gate runs on **both Linux and Windows** and a mutant only fails the gate if
**no platform** caught it. This is because cargo-mutants cannot see `#[cfg]`
([upstream limitation](https://mutants.rs/limitations.html)): a `#[cfg(windows)]`
mutant looks "missed" on Linux (the code isn't compiled there), but the Windows
run catches it — so it isn't flagged. You therefore do **not** need to annotate
platform-specific code just because it shows as missed on one OS.

If code is genuinely not worth a test on any platform (trivial glue), or a
mutant is **equivalent** (semantically identical to the original, so no test can
ever kill it), suppress it and **always explain why**. Pick the narrowest tool:

- **Whole function/item** → the `#[mutants::skip]` attribute, e.g.
  `#[mutants::skip] // reason: <one line>`. NOTE: this attribute needs the
  `mutants` crate as a dependency of that crate (it does not currently have one);
  a bare `#[mutants::skip]` without it fails to compile (`cannot find module
  mutants`). Prefer this for whole items.
- **A single mutant inside a function** (you must keep the function's other
  mutants under test) → a name-anchored `exclude_re` in
  [`.cargo/mutants.toml`](.cargo/mutants.toml). Because cargo-mutants does **not**
  warn when such a regex goes stale (matches nothing) or over-broad (hides a new,
  real survivor), **every `exclude_re` MUST be pinned** in
  [`hack/mutants-check-excludes.py`](hack/mutants-check-excludes.py) to the exact
  mutant(s) it may match; CI (`mutants.yml`) fails on any drift. Add/update the
  pin in the same change.

Only code with a hard requirement on a real VM (KVM/WHP — the VMM drivers and
env-gated integration/e2e harnesses) is excluded wholesale via `exclude_globs` in
[`.cargo/mutants.toml`](.cargo/mutants.toml); do NOT add platform-cfg paths
there. A weekly full run (both platforms) publishes surviving mutants as a
worklist — see
[docs/quality/mutation-gaps-runbook.md](docs/quality/mutation-gaps-runbook.md).
