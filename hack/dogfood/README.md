# izba dogfooding harness

Spec-anchored exploratory bug hunting — see the design at
[`docs/superpowers/specs/2026-06-20-llm-dogfooding-agent-design.md`](../../docs/superpowers/specs/2026-06-20-llm-dogfooding-agent-design.md).

Three phases over two file contracts:

- **Phase 1** (intent extraction) and **Phase 3** (skeptic + synthesis) run
  **locally in Claude Code** (strong model, repo + Greptile access, owner's
  subscription). The repeatable runbook for these is
  [`local-harness.md`](local-harness.md).
- **Phase 2** (the cheap-model journey loop) fans out across KVM CI workers via
  `.github/workflows/dogfood.yml`. See the `run_journeys.py` runner here.

## File contracts

| File | Direction | Schema |
| --- | --- | --- |
| `journeys.json` | Phase 1 → Phase 2 (in) | [`schema/journeys.schema.json`](schema/journeys.schema.json) |
| per-shard trajectory bundle (`traj-<shard>.json`) | Phase 2 → Phase 3 (out) | [`schema/trajectory.schema.json`](schema/trajectory.schema.json) |

## Local Phase 1/3 procedure

The local operator runbook lives in [`local-harness.md`](local-harness.md). It
covers intent extraction (producing `journeys.json` + the dispatch-branch
handoff into CI) and the adversarial skeptic + synthesis pass (turning the
downloaded trajectory bundles into `report.md`).
