# Dogfood deep-sprint: product + harness fixes to unlock deep diff/promote journeys

**Date:** 2026-07-10
**Status:** approved
**Base:** origin/main `bd61471`
**Driver:** the 2026-07-09 LLM-dogfooding re-run of the izba.yml diff/promote/export
surface (3 iterations, converged). Its skeptic verdict: 12 surfaces verified live, but
the deep surface — the 5 semantic validators, the stale-token/Dockerfile TOCTOU legs,
the #124 probe — is **structurally masked** by #122 (the cheap swarm reflexively
rewrites any manifest image-only, and an image-only manifest is rejected at parse), and
the reconcile oracle is **blinded** on every port journey by a ports.json schema bug.

One PR fixes both sides at once — product bugs (#122, #123, #124, the new reconcile
bug) and harness grading gaps (H1–H3, H6, H7) — then re-runs the dogfooding **from the
sprint branch** (`DOGFOOD_BASE`, already supported by `dispatch-swarm.sh:32`; dogfood.yml
builds the izba binary from the dispatched ref at `dogfood.yml:342-343`) to confirm the
previously masked surface before merge.

## 1. Unified sandbox-reference model (#123)

**Mental model (user-facing):** a sandbox is referenced by NAME or by its WORKSPACE
directory; path-looking arguments are workspaces, bare words are names, and no argument
means "the workspace I'm standing in". Git/compose-like; identical across commands.

One shared resolver in `izba-cli` (new `crates/izba-cli/src/commands/sandbox_ref.rs`):

```rust
enum SandboxRef { Workspace(PathBuf), Name(String) }
```

Resolution of an optional positional `arg`:

1. **Omitted** → `Workspace(".")`.
2. **Path syntax** — `arg` is `.` or `..`, contains `/` (or `\` on Windows), or starts
   with `./`/`../` → `Workspace(arg)`. Purely syntactic, never guesses.
3. **Bare word** → if a sandbox of that name exists on disk → `Name(word)` (today's
   behavior for `status/stop/rm`, so nothing breaks). Else if `./word/izba.yml` exists
   → `Workspace(./word)` with a printed one-line note. Else a hint error naming both
   interpretations ("no sandbox 'word' and no ./word/izba.yml — pass a workspace dir
   or an existing sandbox name").
4. **Safety rail** — a bare word that matches an existing sandbox AND has a
   `./word/izba.yml` that resolves to a *different* sandbox name → hard error demanding
   the explicit form (`./word` or `--name`). No silent wrong-target `rm`.

Direction conversions:

- `Name → workspace` (needed by diff/promote/export): read the sandbox's recorded
  `config.json` `workspace` field (`crates/izba-core/src/state.rs:26`,
  `SandboxConfig.workspace`). Honest error if the config or the workspace's `izba.yml`
  is gone.
- `Workspace → name` (needed by status/stop/rm/start): `izba.yml` `metadata.name` if
  the manifest exists (`crates/izba-cli/src/commands/diff.rs:12-24` precedent), else
  `workspace_default_name` (`crates/izba-cli/src/commands/mod.rs:58-64` — canonicalized
  basename, sanitized).

Command wiring:

- `diff` / `promote` / `export` (`crates/izba-cli/src/main.rs:307-327`): the positional
  stays (default `.`), now resolved through the shared resolver — bare names start
  working. The existing `--name` override on diff/export keeps its meaning (override
  the *sandbox name* while the positional supplies the workspace).
- `status` / `stop` / `rm` / `start` (`main.rs:208-234`, `:219`): positional becomes
  **optional**; omitted → the sandbox of the current workspace. Path args accepted.
  Bare-word (name) behavior unchanged.
- `exec` / `ssh` / others keep NAME-only for now (different arg shapes; follow-up).

Docs: `--help` text for all six commands states the model in one line; README gains a
short "Referring to sandboxes" subsection (this is what the swarm reads — the fix is
also a discoverability fix).

Testing: resolver unit tests (table over the four rules + safety rail + missing-config
errors) with tempdir fixtures; command-level tests where they exist today.

## 2. Manifest defaults (#122) — the unlock

`spec.resources` and `spec.rootDisk` become optional with defaults equal to the
product's bare-`izba run` defaults:

- `crates/izba-core/src/manifest/schema.rs:36-65`: `#[serde(default)]` on
  `SandboxSpec.resources` and `SandboxSpec.root_disk`; `impl Default for Resources`
  (cpus 2, memory "4Gi") and `RootDisk` (size "8Gi"). `deny_unknown_fields` stays
  everywhere.
- **Single source of truth**: the default constants move to `izba-core` (new
  `manifest` — or core-level — `defaults`), and `izba-cli`'s
  `DEFAULT_CPUS/DEFAULT_MEM_MB/DEFAULT_RW_GB` (`crates/izba-cli/src/commands/mod.rs:44-47`)
  are re-derived from them (2 cpus = 2, "4Gi" = 4096 MiB, "8Gi" = 8 GiB).
  `DEFAULT_IMAGE` stays CLI-side (the manifest keeps its image-xor-build rule; no
  default image in the schema).
- `export` continues writing explicit `resources`/`rootDisk` (no
  `skip_serializing_if`), so export→diff round-trips are unchanged.
- Docs: README manifest section documents the defaults ("omit resources/rootDisk to
  get 2 cpus / 4Gi / 8Gi").
- **App gate required**: `app/src-tauri` links these types via
  `izba_core::manifest::ops::compute_diff`/`export` (`app/src-tauri/src/commands.rs:230-242`,
  `views.rs:266-327`). No type-shape change (fields stay non-`Option`), but the gate
  runs regardless per CLAUDE.md.

A minimal valid manifest becomes `apiVersion` + `kind` + `spec.image` — the swarm's
reflexive image-only manifests parse, so journeys finally reach the validators and the
review gate.

## 3. `egress_weakens()` false-fire (#124)

`crates/izba-core/src/manifest/diff.rs:67-100`: when `from.enforce == false` the
sandbox allowed everything, so no transition from it can weaken. After the existing
`from.enforce && !to.enforce → true` check, add:

```rust
if !from.enforce {
    return false; // `from` allowed everything; any `to` is no weaker
}
```

Regression tests: `enforce:false→true` **with allow entries** is not flagged (the
dogfood repro); `false→false` with added allows is not flagged; the existing
on→off/verb-widening/git-rule tests (`diff.rs:270-439`) keep passing.

## 4. Reconcile ports.json schema (NEW-1)

`crates/izba-core/src/reconcile.rs:119-152` reads `ports.json` as the legacy
`Vec<PortRecord>` (`state.rs:66-70`) while the daemon writes `Vec<PortRule>`
(`daemon/relays.rs:26-28` `save_rules`) — every current-format file fails with
``missing field `rule` `` and reconcile returns a false-empty snapshot, which also
blinds the dogfood reconcile oracle on port journeys.

Fix:

- Replace the load with `daemon::relays::load_rules_migrating(paths, name)`
  (`relays.rs:31-51`, already `pub`, same crate) → `(Vec<PortRule>, Vec<PidIdentity>)`.
- Rework the orphan-relay check (`reconcile.rs:126-152`): the "relay dead while
  sandbox alive" direction is **deleted** (relays are daemon threads; no pid is
  persisted). Any **alive legacy relay pid** returned by migration becomes a violation
  ("legacy relay process (pid N) alive; relays are daemon threads now").
- TDD: a test writing a current-schema `Vec<PortRule>` ports.json fails against
  today's code and passes after; the legacy-schema path keeps a test (alive legacy pid
  → violation). The existing `relay_dead_while_sandbox_running_is_orphan_relay`
  (`reconcile.rs:289-317`) is replaced accordingly.

## 5. Graduation tests (deep legs the swarm can't reach)

The 5 semantic validators are already pinned (`schema.rs:187-226`:
unknown-apiVersion/kind, image-xor-build both/neither, unknown-field; traversal in
`ops.rs:469-491` + `promote.rs:306`). Graduation is gap-fill only:

- **Dockerfile-change TOCTOU**: unit test combining `store.rs review_token`
  (`store.rs:19-27`) + the promote `gate` (`promote.rs:32-40`): token computed with
  Dockerfile A, gate re-checked against token with Dockerfile B → `Stale`; manifest
  edit after diff → `Stale` (complements `gate_detects_stale_review`).
- **#124 matrix** (§3) and **NEW-1 schema tests** (§4).
- **daemon_e2e extension** (`crates/izba-cli/tests/daemon_e2e.rs:591`
  `manifest_diff_promote_live_path`): promote an egress-only change on a running
  sandbox → vmm pid unchanged + `policy show` reflects the change (live hot-reload,
  the strongest behavior the run verified); promote on a stopped sandbox → the
  `sandbox not running — changes apply on next start` skip. KVM-gated, runs in e2e.yml.

## 6. Harness grading fixes (H1–H3, H6, H7)

All in `hack/dogfood/`, each with tests in the existing suite (169 tests, `dogfood-harness`
CI job, `ci.yml:107-126`).

- **H1 — grade the product command, not the heredoc.**
  `run_journeys.py:271-310` `_grade_step_functional` target selection becomes:
  `expect_cmd_re` match (existing, still wins) → else the **last action whose command
  invokes the izba binary** (word-boundary match on `izba` / the basename of
  `--izba-bin`) → else the final action (current behavior). Seed-write heredocs stop
  absorbing the step's `expect_exit`.
- **H2 — informational reconcile items don't flip.**
  `run_journeys.py:238-250`: filter out violations whose `detail` starts with
  `informational:` (the product contract — sole producer at
  `crates/izba-core/src/reconcile.rs:174-181`, pinned by its own test) before
  building the `reconcile_violation` candidate; count/preview use the filtered list;
  no candidate when only informational items remain. Full snapshot stays in
  `state_evidence` for the skeptic.
- **H3 — decisive coverage by observed commands.**
  `run_journeys.py:500-516`: before emitting `unreached_decisive` for a decisive step
  with zero own actions, scan **all** journey actions for the last command matching the
  step's `expect_cmd_re`; if found, grade it with `functional_oracle` (same
  expect/expect_exit, tagged decisive) instead of flagging unreached. No
  `expect_cmd_re` or no match → current behavior. Authoring guidance (schema
  description + `local-harness.md` + journey-compiler agent notes): decisive steps
  should declare `expect_cmd_re`.
- **H6 — console evidence on action timeout.**
  `oracles.py:174-178` (exit-124 path): append the tail (last 8 KiB, existing
  `CONSOLE_TAIL_BYTES`) of every `<data_dir>/sandboxes/*/logs/console.log` to the
  action's `stderr_tail` as `[harness] console.log tail (<name>): …`. **No auto-retry**
  (deliberate deviation from the run's draft recommendation: a retry would mask real
  latency/stall findings; the skeptic adjudicates with the console evidence in hand).
- **H7 — starvation tally instead of per-reply infra spam.**
  `run_journeys.py:313-335` `_next_command` stops appending one `infra` candidate per
  failed model turn (garbled JSON / model exception); failures are tallied per journey
  and emitted as **one** `infra` candidate ("model starved: N failed turn(s); first:
  …"). `count_degraded` (`:69-75`) and the exit-3 threshold (`:65-66`, `:670-694`)
  semantics are unchanged (any infra candidate still marks the journey degraded); the
  collector's flipping `negatives` stop being inflated. The outer crashed-journey
  infra candidate (`:662-667`) stays as-is.

No trajectory-schema changes (no new candidate kinds; H6 rides in `stderr_tail`).

## 7. Sprint mechanics + acceptance re-run

- **One PR** off branch `worktree-dogfood-deep-sprint` (this worktree, cut from
  `bd61471`). Subagent-driven implementation per the plan; conventional commits; PR
  closes #122/#123/#124 and describes NEW-1 + H-fixes (the standalone issue drafts
  from 2026-07-09 become optional).
- **Mid-sprint swarm iteration** (no merge needed):
  `DOGFOOD_BASE=origin/worktree-dogfood-deep-sprint .claude/skills/llm-dogfooding/scripts/dispatch-swarm.sh …`
  — the run branch is cut from the sprint tip and dogfood.yml builds both harness and
  izba from it. `ci.yml` ignores `dogfood-run/**` so dispatch branches fire no gates.
- **Acceptance re-run**: journey-compiler recompiles a fresh journey set against the
  *branch's* README/`--help` (fair-test boundary intact — the docs changes in §1/§2 are
  part of what's under test), targeted at the previously masked surface: the 5
  semantic validators, stale-token + Dockerfile-change TOCTOU refusals, the #124
  probe, name/dir reference UX, and port-publish journeys (NEW-1 unblinds the
  reconcile oracle). ~12 journeys, 4 shards, max_usd 2/shard. Trajectory-skeptic
  triage closes the loop; findings → issues.
- **Gates before merge-ready**: the six workspace gates, the app gate (§2), the
  `dogfood-harness` pytest job, SonarCloud, Greptile.

## Out of scope

- `exec`/`ssh` adopting the sandbox-reference resolver (follow-up).
- A product-side `severity` field on reconcile violations (the `informational:` prefix
  is the contract; YAGNI for now).
- Auto-retry of timed-out actions (rejected — masks findings).
- Filing the 2026-07-09 standalone issue drafts (superseded by this PR unless the
  owner wants tracking issues anyway).
