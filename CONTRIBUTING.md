# Contributing to izba

See [CLAUDE.md](CLAUDE.md) for the build/test gates and architecture, and
[docs/](docs/) for design specs. This file collects contributor-facing rules
that do not belong in the build docs.

## Mutation testing (cargo-mutants)

CI runs [`cargo-mutants`](https://mutants.rs): the incremental PR gate
(`.github/workflows/mutants.yml`) fails if any mutant on your changed lines
survives — i.e. no test notices when cargo-mutants alters that code. To fix,
add a test that would catch the mutation.

If a line is genuinely not worth a test (trivial glue, host-unkillable VMM
code), annotate it and **always explain why**:

```rust
#[mutants::skip] // reason: <one line — why this mutant is not worth a test>
```

Host-unkillable subsystems (KVM/VMM/real-VM paths) are excluded wholesale in
[`.cargo/mutants.toml`](.cargo/mutants.toml); extend those globs rather than
scattering skips. A weekly full run publishes surviving mutants as a worklist —
see [docs/quality/mutation-gaps-runbook.md](docs/quality/mutation-gaps-runbook.md).
