# GUI Manifest Surface + GUI Dogfood Deep-Sprint Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Tauri app's missing izba.yml diff/promote/export UI and extend the GUI dogfooding harness to drive and honestly grade it, in one PR.

**Architecture:** Extract the CLI's promote orchestration into `izba-core::manifest::promote` (event-callback design keeps CLI output byte-identical); app manifest commands become name-only (backend resolves workspace from managed config); a new ManifestTab renders `DiffView` with a promote confirm flow; the headless dogfood bridge gains manifest dispatch arms; both journey runners gain step-level `seed_files`; a `manifest_truth` oracle gives GUI journeys functional/decisive grading.

**Tech Stack:** Rust (izba-core, izba-cli, Tauri 2 src-tauri), React + TypeScript (vitest, Playwright), Python (hack/dogfood harness, pytest).

**Spec:** `docs/superpowers/specs/2026-07-11-gui-manifest-dogfood-design.md`

## Global Constraints

- **CLI promote/diff output stays byte-identical** — stdout/stderr strings and exit codes unchanged; existing CLI unit tests and `daemon_e2e` steps pin this. Never alter a printed string during the extraction.
- App manifest commands take **`name` only**; workspace comes from `izba_core::state::{load_json, SandboxConfig, CONFIG_FILE}` (`paths.sandbox_dir(name).join(CONFIG_FILE)`), never from the frontend.
- The app's `manifest_diff` **persists the review token** (`store::write_review`) — rendering the diff IS the review. No `--force` equivalent anywhere in the GUI.
- **No `DAEMON_PROTO_VERSION` bump** — promote reuses existing daemon RPCs only.
- Worktree toolchain: `export RUSTUP_HOME=/home/kolkhovskiy/git/izba/.toolchain/rustup CARGO_HOME=/home/kolkhovskiy/git/izba/.toolchain/cargo PATH=/home/kolkhovskiy/git/izba/.toolchain/cargo/bin:$PATH` before any cargo command (`.cargo-env` is `$PWD`-relative and does not work in worktrees).
- Rust gates for any crates/ change: `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check`, izba-init musl build, the two `x86_64-pc-windows-gnu` cross gates.
- App gate for any app/ or izba-core public-type change: `cd app && npm ci && npm run build && (cd src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test)`.
- Dogfood harness: `python3 -m pytest hack/dogfood` must pass (CI gate).
- SonarCloud: new frontend code needs vitest coverage; React props `Readonly`; no `npx` in workflow YAML; no hardcoded non-doc IPs in tests.
- Exact UI copy strings in Task 5/6 are load-bearing (vitest asserts + dogfood `dom_expect` oracle keywords) — use them verbatim.
- Frontend components follow the existing shadcn + `app/src/components/` patterns; tests follow `app/src/test/*.test.tsx` conventions (vitest + @testing-library/react).
- Conventional commits, one commit per green TDD cycle.

---

### Task 1: Extract promote orchestration into izba-core (CLI byte-parity)

**Files:**
- Create: `crates/izba-core/src/manifest/promote.rs`
- Modify: `crates/izba-core/src/manifest/mod.rs` (add `pub mod promote;`)
- Modify: `crates/izba-cli/src/commands/promote.rs` (becomes resolver + renderer)
- Test: unit tests move with the code into `crates/izba-core/src/manifest/promote.rs`; CLI keeps its resolver-level tests.

**Interfaces:**
- Consumes: `manifest::{store, ops, diff::{FieldDelta, DriftState}}`, `daemon::DaemonClient`, existing `DaemonRequest` variants (no new wire types).
- Produces (later tasks rely on these exact names):

```rust
// crates/izba-core/src/manifest/promote.rs
#[derive(Debug, PartialEq, Eq)]
pub enum GateOutcome { /* MOVE VERBATIM from crates/izba-cli/src/commands/promote.rs:15-28 — keep the existing variant names exactly (Ok, ForcedUnreviewed, ForcedStale, plus the two refusal variants as named there) */ }

pub fn gate(review: Option<&str>, current_token: &str, force: bool) -> GateOutcome;

#[derive(Debug, Clone, Copy, Default)]
pub struct PromoteOpts { pub force: bool, pub restart: bool, pub reset_scratch: bool }

#[derive(Debug)]
pub enum PromoteEvent { Info(String), Warn(String) }

#[derive(Debug)]
pub struct PromoteOutcome {
    pub state: DriftState,
    pub applied: Vec<FieldDelta>,   // deltas actually applied this run
    pub needs_restart: bool,        // restart/image-class deltas remain pending
    pub restarted: bool,            // opts.restart executed a restart
    pub stopped: bool,              // sandbox stopped; changes apply on next start
    pub warnings: Vec<String>,      // every Warn message, in emit order
}

/// dir = repo workspace (contains izba.yml); name = RESOLVED sandbox name.
pub fn run(
    paths: &Paths,
    dir: &Path,
    name: &str,
    opts: PromoteOpts,
    on_event: &mut dyn FnMut(PromoteEvent),
) -> anyhow::Result<PromoteOutcome>;
```

**Steps:**

- [ ] **Step 1: Move the gate.** Move `GateOutcome` + `gate()` and their unit tests (`gate_requires_a_token`, `gate_detects_stale_review`, `gate_passes_on_match`, `dockerfile_change_invalidates_review_token`, `validate_name_rejects_traversal` stays in CLI if it tests the CLI arg path) from `crates/izba-cli/src/commands/promote.rs` into the new `crates/izba-core/src/manifest/promote.rs`. In the CLI file add `pub(crate) use izba_core::manifest::promote::{gate, GateOutcome};` so any intra-crate references keep compiling. Run `cargo test -p izba-core manifest::promote -p izba-cli promote` — the moved tests pass unchanged.

- [ ] **Step 2: Move the orchestration.** Transplant everything in CLI `run()` AFTER the `sandbox_ref::resolve`/`check_name_override`/workspace resolution block (i.e. from `load_repo_manifest(dir)` through the final `store::advance_base`/`clear_review`) into `promote::run(paths, dir, name, opts, on_event)`. Mechanical rules:
  - Every `println!("...")` becomes `on_event(PromoteEvent::Info(format!("...")))` with the SAME string.
  - Every `eprintln!("...")` becomes `emit_warn(...)` — a local helper that pushes the string into `outcome.warnings` AND calls `on_event(PromoteEvent::Warn(...))` with the SAME string.
  - Every `bail!`/`Err` keeps its exact message (the CLI's exit-code behavior rides on anyhow errors).
  - `force`/`restart`/`reset_scratch` locals read from `opts`.
  - Populate `PromoteOutcome` fields from the values the code already computes (drift state, the applied delta list, the stopped-skip branch at the old `promote.rs:198` area, the restart branch).
- [ ] **Step 3: Rewire the CLI.** CLI `run()` keeps: resolver, `check_name_override`, workspace extraction, `validate_name`, then:

```rust
let outcome = izba_core::manifest::promote::run(
    paths, dir, &name,
    izba_core::manifest::promote::PromoteOpts { force, restart, reset_scratch },
    &mut |ev| match ev {
        izba_core::manifest::promote::PromoteEvent::Info(m) => println!("{m}"),
        izba_core::manifest::promote::PromoteEvent::Warn(m) => eprintln!("{m}"),
    },
)?;
let _ = outcome; // CLI output is fully carried by the events
Ok(0)
```

  Preserve any code path where the CLI returned a non-zero exit or early return — check the current file for every `return`/`Ok(...)` and keep semantics identical.
- [ ] **Step 4: Byte-parity check.** Run the full existing test evidence: `cargo test -p izba-cli` (promote/diff unit tests) and `cargo test -p izba-core`. Then `git grep -n "eprintln!\|println!" crates/izba-core/src/manifest/promote.rs` must return ZERO hits (all output flows through events).
- [ ] **Step 5: Add a core-level outcome test.** In `promote.rs` tests: a fake-free test of the gate error messages via `run` is not possible without a daemon — instead unit-test `PromoteOpts::default()` is all-false and that `gate` outcomes map as before. The orchestration remains covered by `daemon_e2e` steps [9]-[11] (do NOT weaken them).
- [ ] **Step 6: All six workspace gates** (see Global Constraints), then commit: `refactor(core): extract promote orchestration into izba-core::manifest::promote (event-callback, CLI byte-parity)`.

### Task 2: App backend — name-only manifest cores + review token + promote core + PromoteView

**Files:**
- Modify: `app/src-tauri/src/commands.rs` (manifest cores at :227-245 + tests module)
- Modify: `app/src-tauri/src/views.rs` (add `PromoteView`; tests near `diff_view_maps_state_and_deltas` at :324)

**Interfaces:**
- Consumes: Task 1's `manifest::promote::{run, PromoteOpts, PromoteEvent, PromoteOutcome}`; `izba_core::state::{load_json, SandboxConfig, CONFIG_FILE}`; `ops::{compute_diff, export}`; `store::write_review`.
- Produces:

```rust
// commands.rs
fn workspace_for(paths: &Paths, name: &str) -> Result<PathBuf, String>; // config.json → workspace; err "sandbox '<name>' not found" / "sandbox '<name>' has no recorded workspace"
pub fn manifest_diff_core(name: &str) -> Result<views::DiffView, String>;   // WRITES review token
pub fn manifest_export_core(name: &str) -> Result<String, String>;
pub fn manifest_promote_core(name: &str, restart: bool) -> Result<views::PromoteView, String>;

// views.rs
#[derive(Serialize, Debug)]
pub struct PromoteView {
    pub state: String,               // same mapping as DiffView
    pub applied: Vec<DeltaView>,
    pub needs_restart: bool,
    pub restarted: bool,
    pub stopped: bool,
    pub warnings: Vec<String>,
}
impl PromoteView { pub fn new(o: izba_core::manifest::promote::PromoteOutcome) -> Self { /* reuse DiffView's state/delta mapping helpers */ } }
```

**Steps:**

- [ ] **Step 1 (test first):** In `views.rs` tests add `promote_view_maps_outcome` building a `PromoteOutcome` with one live delta + one warning and asserting the serialized shape (`state == "repo_ahead"`, `applied[0].class == "live"`, `warnings == ["w"]`). Run: fails (no PromoteView). Implement `PromoteView` (extract the state/class mapping used by `DiffView::new` into shared private helpers — do not duplicate the match). Test passes.
- [ ] **Step 2 (test first):** In `commands.rs` tests add `manifest_diff_core_resolves_workspace_and_writes_review`: with `IZBA_DATA_DIR` pointed at a tempdir (see existing tests' env pattern in this file), create `sandboxes/<name>/config.json` recording a temp workspace containing a minimal `izba.yml` (image-only — defaults from PR #129 make it valid), call `manifest_diff_core(name)`, assert Ok + `store::read_review(&paths.sandbox_dir(name))` is `Some`. Add `manifest_diff_core_missing_sandbox_err` asserting the "not found" message. Run: fails. Implement `workspace_for` + rewrite `manifest_diff_core`/`manifest_export_core` to name-only (delete the `workspace: &str` params), diff now calls `store::write_review(&paths.sandbox_dir(name), &token)`. Tests pass.
- [ ] **Step 3:** Implement `manifest_promote_core(name, restart)`: `workspace_for` → `izba_core::manifest::promote::run(&paths, &ws, name, PromoteOpts{force:false, restart, reset_scratch:false}, &mut |_|{})` → `PromoteView::new(outcome)`, `map_err(|e| e.to_string())`. Mark `#[allow(dead_code)]` not needed (wired in Task 3 same PR — if clippy complains before Task 3, wire order says Task 3 lands next; use `pub` visibility which silences it in a lib target). No daemon in unit tests: assert only the error path `manifest_promote_core("ghost", false)` → Err containing "not found".
- [ ] **Step 4:** App gate (`cd app/src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`). Commit: `feat(app): name-only manifest cores, review-token parity, promote core + PromoteView`.

### Task 3: Tauri shims + headless dispatch arms

**Files:**
- Modify: `app/src-tauri/src/lib.rs` (shims :317-329, `invoke_handler` :549-550, `dispatch` match :462-497, dispatch tests :556+)

**Interfaces:**
- Consumes: Task 2's three cores.
- Produces: Tauri commands `manifest_diff(name)`, `manifest_export(name)`, `manifest_promote(name, restart)`; dispatch arms with identical names/args. Frontend (Task 4) invokes exactly these.

**Steps:**

- [ ] **Step 1 (test first):** In lib.rs dispatch tests add `dispatch_manifest_diff_unknown_sandbox`: `dispatch("manifest_diff", json!({"name":"ghost"}), ...)` returns Err containing "not found" (NOT "unknown command"). Same for `manifest_export` and `manifest_promote` (promote args `{"name":"ghost","restart":false}`). Run: fails with "unknown command".
- [ ] **Step 2:** Update the two existing `#[tauri::command]` shims to name-only, add the promote shim (async over `spawn_blocking`, mirroring :317-329):

```rust
#[tauri::command]
async fn manifest_promote(name: String, restart: bool) -> Result<views::PromoteView, String> {
    tauri::async_runtime::spawn_blocking(move || commands::manifest_promote_core(&name, restart))
        .await
        .map_err(|e| e.to_string())?
}
```

  Register in `generate_handler!`. Add dispatch arms (these cores don't touch the `d` daemon lock — place them BEFORE the `state.daemon.lock()` block if the borrow requires, else inside the match as plain arms):

```rust
"manifest_diff" => to_json(commands::manifest_diff_core(&arg_str(&args, "name")?)?),
"manifest_export" => to_json(commands::manifest_export_core(&arg_str(&args, "name")?)?),
"manifest_promote" => {
    let restart = args.get("restart").and_then(|v| v.as_bool()).unwrap_or(false);
    to_json(commands::manifest_promote_core(&arg_str(&args, "name")?, restart)?)
}
```

- [ ] **Step 3:** Tests pass; app gate; commit: `feat(app): manifest_promote command + manifest dispatch arms for the dogfood bridge`.

### Task 4: Frontend plumbing — TS types, ipc bridge, e2e mock

**Files:**
- Modify: `app/src/lib/types.ts`, `app/src/lib/ipc.ts` (:20-67), `app/e2e/mock/tauri-mock.js` (:84-159)
- Test: `app/src/test/ipc.test.ts` (extend existing)

**Interfaces:**
- Produces (Task 5/6 consume):

```ts
// types.ts
export type DriftState = "in_sync" | "repo_ahead" | "managed_ahead" | "diverged";
export interface DeltaView { field: string; from: string; to: string; class: "live" | "restart" | "image"; weakens_egress: boolean; }
export interface DiffView { state: DriftState; deltas: DeltaView[]; }
export interface PromoteView { state: DriftState; applied: DeltaView[]; needs_restart: boolean; restarted: boolean; stopped: boolean; warnings: string[]; }

// ipc.ts api object
manifestDiff(name: string): Promise<DiffView>       // invoke("manifest_diff", { name })
manifestExport(name: string): Promise<string>       // invoke("manifest_export", { name })
manifestPromote(name: string, restart: boolean): Promise<PromoteView>  // invoke("manifest_promote", { name, restart })
```

**Steps:**

- [ ] **Step 1 (test first):** extend the existing ipc test pattern: mock `invoke`, assert `api.manifestDiff("a")` calls `invoke("manifest_diff", { name: "a" })` and returns the value; same for the other two. Fails (methods missing).
- [ ] **Step 2:** add the three types + three `api` methods following the file's existing wrapper style. Tests pass.
- [ ] **Step 3:** `tauri-mock.js`: add cases returning canned data controlled by a `window.__MOCK_MANIFEST__` override (default: `manifest_diff` → `{state:"repo_ahead", deltas:[{field:"policy.egress.enforce", from:"true", to:"false", class:"live", weakens_egress:true}]}`; `manifest_export` → `"/ws/izba.yml"`; `manifest_promote` → `{state:"in_sync", applied:[...same delta], needs_restart:false, restarted:false, stopped:false, warnings:["promote: ⚠ weakens egress"]}`). Follow the mock's existing case style.
- [ ] **Step 4:** `npm run test -- ipc` green; `npm run lint`; commit: `feat(app): manifest TS types + ipc bridge + e2e mock cases`.

### Task 5: ManifestTab — read-only diff view + Export

**Files:**
- Create: `app/src/components/ManifestTab.tsx`
- Modify: `app/src/components/Detail.tsx` (:22 tab union, :77-85 tab bar, tab content switch)
- Test: `app/src/test/manifestTab.test.tsx`

**Interfaces:**
- Consumes: `api.manifestDiff`, `api.manifestExport`, types from Task 4. Props: `{ name: string; running: boolean }` (Detail already knows both).
- Produces: `<ManifestTab name={...} running={...} />`; tab id `"manifest"`, tab label `Manifest`.

**Exact copy (verbatim — tests and dogfood oracles key on these):**
- `in_sync` banner: `In sync — izba.yml and managed settings match.`
- `repo_ahead` banner: `izba.yml has changes not yet applied. Review below, then Promote.`
- `managed_ahead` banner: `Live settings have drifted from izba.yml. Export to capture them.`
- `diverged` banner: `Both izba.yml and managed settings changed. Promote applies izba.yml; Export overwrites it.`
- class chips: `live` / `restart` / `image`; chip tooltips: `applies immediately` / `applies on next start` / `image change — applies on next start`
- weakens marker (inline in the delta row): `⚠ weakens egress`
- empty deltas: `No field changes between izba.yml and managed settings.`
- missing manifest (error containing "izba.yml"): heading `No izba.yml found in this sandbox's workspace.` body `Create an izba.yml in the workspace to manage this sandbox declaratively — the manifest describes image, resources, ports, volumes and firewall policy. Run 'izba export <name>' or use Export here after making changes in the app.`
- buttons: `Refresh`, `Export to izba.yml`, `Promote…`
- export success line: `Exported to {path}`

**Steps:**

- [ ] **Step 1 (tests first)** in `manifestTab.test.tsx`, mocking `api` like sibling tests do: (a) fetches on mount and renders the `repo_ahead` banner + a delta row `policy.egress.enforce` with chip `live` and `⚠ weakens egress`; (b) `in_sync` renders its banner and both Promote/Export disabled with title-attribute hints (`Nothing to promote — izba.yml has no unapplied changes.` / `Nothing to export — no managed-side drift.`); (c) `managed_ahead` enables Export, click → `api.manifestExport` called → `Exported to /ws/izba.yml` appears; (d) manifestDiff rejection with message containing `izba.yml` renders the missing-manifest guidance heading; other errors render the raw message in the tab's error area; (e) Refresh re-calls manifestDiff. Run: all fail.
- [ ] **Step 2:** implement ManifestTab: `useState<DiffView|null>` + `error` + `exportedPath`; `useEffect` fetch on mount + name change; enablement matrix — Promote enabled iff `state ∈ {repo_ahead, diverged}`, Export enabled iff `state ∈ {managed_ahead, diverged}`; delta table (plain table, existing table styles); banner as a colored callout (reuse existing alert/callout classes from PolicyEditor/Overview). The Promote button is rendered with correct enablement in this task; clicking it sets a `promoteOpen` boolean state that Task 6's dialog consumes. Tests in this task assert enablement + hints only.
- [ ] **Step 3:** wire into Detail.tsx: add `"manifest"` to the tab union + `Manifest` tab button (after `policy`) + render `<ManifestTab name={sb.name} running={...} />`; extend an existing Detail test to assert the tab button exists and switches.
- [ ] **Step 4:** `npm run test`, `npm run lint`, `npm run build`. Commit: `feat(app): Manifest tab — drift banner, delta table, export flow`.

### Task 6: Promote flow — confirm dialog, weakens-egress ack, outcome rendering

**Files:**
- Modify: `app/src/components/ManifestTab.tsx`
- Test: `app/src/test/manifestTab.test.tsx` (extend)

**Interfaces:** Consumes `api.manifestPromote`. Dialog built with the existing dialog component used by NewSandbox (shadcn `Dialog`).

**Exact copy:**
- dialog title: `Promote izba.yml changes`
- dialog body intro: `The following changes will be applied to '{name}':`
- restart note (shown when any delta class ≠ live OR `running` is false): `Changes that need a restart apply on the next start.`
- restart checkbox (shown only when running AND any delta class ∈ {restart, image}): `Restart now to apply restart-class changes`
- weakens ack checkbox (shown when any listed delta has `weakens_egress`): `I understand this weakens the egress firewall`
- confirm button: `Promote` (disabled until weakens ack checked, when required)
- stale-token error (error containing "izba.yml changed"): `izba.yml changed since you viewed this diff. Refresh and review again.`
- never-reviewed error (error containing "no reviewed diff"): `Review the diff first — open this tab's latest state, then Promote.`
- success summary: `Promoted {n} change(s).` plus, when `stopped`: `Sandbox is stopped — changes apply on next start.`; when `needs_restart`: `Some changes apply on the next restart.`; each `warnings[]` entry rendered as a warning line.

**Steps:**

- [ ] **Step 1 (tests first):** (a) clicking `Promote…` (repo_ahead fixture) opens the dialog listing the delta fields; (b) with a `weakens_egress` delta the `Promote` confirm stays disabled until the ack checkbox is checked; (c) confirm calls `api.manifestPromote(name, false)` and renders `Promoted 1 change(s).` + warning lines + diff refetch (manifestDiff called again); (d) restart checkbox appears for a `restart`-class delta when `running`, and checking it calls `manifestPromote(name, true)`; (e) promote rejection containing `izba.yml changed` renders the stale-token copy; containing `no reviewed diff` renders the never-reviewed copy. Run: fail.
- [ ] **Step 2:** implement dialog + outcome state + error mapping (substring match on the two known gate errors, raw message otherwise). After a successful promote always refetch the diff.
- [ ] **Step 3:** `npm run test`, lint, build. Commit: `feat(app): promote confirm flow with weakens-egress acknowledgment`.

### Task 7: NewSandbox disabled-Create feedback (first-run P1)

**Files:**
- Modify: `app/src/components/NewSandbox.tsx` (`canCreate` :145, button :365)
- Test: `app/src/test/newSandbox.test.tsx` (extend existing)

**Steps:**

- [ ] **Step 1 (test first):** with empty required fields, a hint list appears under the Create button: `Name is required.` / `Image is required.` / `Workspace folder is required.` (only the missing ones; invalid name shows the validation message the backend would give: `Name must be lowercase letters, digits and dashes.` — check `validate_name` rules in `crates/izba-core/src/sandbox.rs` and mirror the constraint text, keep it one line). Button keeps `disabled`.
- [ ] **Step 2:** implement: derive `missing: string[]` from the same predicates `canCreate` uses (refactor the boolean into a list so they cannot drift), render as muted small text; `aria-describedby` on the button.
- [ ] **Step 3:** tests green, lint, build. Commit: `fix(app): explain why Create is disabled in New sandbox (first-run P1)`.

### Task 8: Playwright e2e — manifest spec over the mock

**Files:**
- Create: `app/e2e/manifest.spec.ts` (follow `app/e2e/policy.spec.ts` structure)

**Steps:**

- [ ] **Step 1:** spec: open app with mock, select the mocked sandbox, click `Manifest` tab → `repo_ahead` banner + `⚠ weakens egress` visible; click `Promote…` → dialog; ack checkbox → confirm → `Promoted 1 change(s).`; override `window.__MOCK_MANIFEST__` to `managed_ahead` → `Export to izba.yml` → `Exported to /ws/izba.yml`.
- [ ] **Step 2:** run the e2e suite the way CI does (`npm run e2e` or the project's script — check `app/package.json`); green. Commit: `test(app): manifest tab e2e spec`.

### Task 9: Step-level seed_files — schema + CLI runner

**Files:**
- Modify: `hack/dogfood/schema/journeys.schema.json` (step object), `hack/dogfood/run_journeys.py` (seeding + step loop), `hack/dogfood/schema/trajectory.schema.json` only if the bundle records seeds (it should not — no change expected)
- Test: `hack/dogfood/test_run_journeys.py` (extend)

**Interfaces:** step gains optional `seed_files: {path: content}` (same shape as the journey-level field, `:62-66`); files are written relative to the journey workspace immediately BEFORE the step's first action, after cwd setup. Journey-level `seed_files` keeps meaning "before step 0".

**Steps:**

- [ ] **Step 1 (test first):** pytest: a two-step journey where step 1 has `seed_files: {"izba.yml": "spec:\n  image: alpine\n"}`; run with the fake-model path the existing tests use; assert the file exists in the workspace when step 1's action executes (fake action `cat izba.yml` capturing content) and does NOT exist during step 0. Schema-validation test: step-level `seed_files` accepted; non-object rejected.
- [ ] **Step 2:** implement: extract the existing journey-level seeding into `_write_seeds(workspace, mapping)`; call it with the journey mapping before step 0 and with `step.get("seed_files")` at each step boundary. Add the field to the schema step definition with the same description discipline (note: seeding is for PRECONDITIONS, decisive steps must not be graded on seed writes — reuse the existing journey-level wording).
- [ ] **Step 3:** `python3 -m pytest hack/dogfood` green. Commit: `feat(dogfood): step-level seed_files for mid-journey preconditions`.

### Task 10: GUI runner — workspace dir, seeding, {workspace} substitution

**Files:**
- Modify: `hack/dogfood/gui/run_gui_journeys.py`
- Test: `hack/dogfood/gui/test_run_gui_journeys.py` (extend)

**Interfaces:** each GUI journey gets `workspace = <journey_data_dir>/workspace` (created); journey-level + step-level `seed_files` written there (reuse `_write_seeds` from Task 9 via import — `from hack.dogfood.run_journeys import _write_seeds` follows however the gui module currently imports CLI-side helpers, see `run_gui_journeys.py:29-31`); every step `intent` (and step `expect`) has the literal token `{workspace}` replaced with the absolute path before being shown to the Actor.

**Steps:**

- [ ] **Step 1 (tests first):** (a) journey with journey-level seed → file exists under `<data_dir>/workspace` before step 0 (drive with `--fake-model`); (b) step-level seed lands before that step; (c) an intent `Create a sandbox with workspace {workspace}` reaches the fake Actor with the real absolute path substituted (assert via the recorded trajectory step intent or the model-call fixture); (d) `{workspace}` in `expect` is substituted before `dom_expect` keyword extraction.
- [ ] **Step 2:** implement in the per-journey setup (`:334` area) + the step loop; store `workspace` in the trajectory journey dict (`"workspace": str(path)`) for the skeptic.
- [ ] **Step 3:** pytest green; run `hack/dogfood/gui/smoke.sh` (fake-model, no KVM) to prove the plumbing end-to-end. Commit: `feat(dogfood-gui): per-journey workspace with seed_files + {workspace} substitution`.

### Task 11: Honest GUI grading — invoke digest, manifest_truth oracle, decisive wiring

**Files:**
- Modify: `app/dogfood/real-bridge.js` (invoke log :32-36), `hack/dogfood/gui/gui_oracles.py`, `hack/dogfood/gui/run_gui_journeys.py` (grading, `:180-219`), `hack/dogfood/schema/trajectory.schema.json` (action `invoke_log` entry gains optional `digest`)
- Test: `hack/dogfood/gui/test_gui_oracles.py`, `hack/dogfood/gui/test_run_gui_journeys.py`

**Interfaces:**
- `real-bridge.js`: for `cmd.startsWith("manifest_")`, the `__DF_INVOKE_LOG__` entry gains `digest`: for `manifest_diff` → `{state, deltas: n, weakens: k}`; `manifest_promote` → `{state, applied: n, needs_restart, stopped}`; `manifest_export` → `{path}` (strings/bools/ints only — keep it tiny).
- `manifest_truth_oracle(ctx)` in `gui_oracles.py`: fires only when the journey's invoke log contains a `manifest_diff` digest; runs the CLI as ground truth using the PR #129 surface — `izba diff <workspace-path> --name <name>` (path-syntax positional selects the workspace, explicit `--name` pins the sandbox, cwd-independent) against the shared `IZBA_DATA_DIR`. Compare the CLI-computed drift state (parse the `state: <label>` line, map labels back to the enum strings) against the LAST `manifest_diff` digest's `state`. Mismatch ⇒ candidate `kind: "functional"`, reason prefixed `manifest_truth:`. **Side-effect constraint:** CLI `izba diff` writes the review token; the oracle therefore runs only POST-journey (where the runner already grades), never between steps — a mid-journey run would refresh the token and mask stale-token behavior under test. State this in the oracle docstring and keep the oracle out of any per-step hook. The sandbox name comes from the reconcile snapshot (existing `capture_state_evidence` plumbing) or, simpler, from a new ctx field: the last `create` invoke's opts name — pick whichever the existing ctx structure already carries; document the choice in the oracle docstring.
- Decisive wiring: GUI journeys support step-level `core: true` exactly like CLI; `run_gui_journeys.py` grades the decisive step by whether a `functional` candidate (from `manifest_truth`) targets it — reuse the CLI grading helpers from `run_journeys.py` (import, don't copy; if they're too CLI-shaped, extract the shared piece into `hack/dogfood/grading.py` used by both runners — prefer the extraction if any signature would need faking).

**Steps:**

- [ ] **Step 1 (tests first, oracle):** synthetic ctx with a diff digest `state: "in_sync"` while the CLI truth (mock the subprocess call via injectable runner fn) reports `repo ahead (promotable)` ⇒ one functional candidate; matching states ⇒ no candidate; no manifest invoke ⇒ oracle silent.
- [ ] **Step 2 (tests first, digest):** extend the bridge — since real-bridge.js has no JS test rig, test via the GUI runner's parse path: a fixture invoke-log JSON with `digest` fields round-trips into the trajectory bundle and validates against the schema.
- [ ] **Step 3 (tests first, decisive):** fake-model GUI journey with a `core: true` step and an injected mismatching truth ⇒ journey grades negative with `unreached/failed` semantics matching the CLI runner's; matching truth ⇒ positive WITH `decisive_credits` recorded (schema parity with PR #129's audit trail).
- [ ] **Step 4:** implement all three; schema update for `digest`; `python3 -m pytest hack/dogfood` green; smoke.sh green. Commit: `feat(dogfood-gui): manifest_truth oracle + functional decisive grading for GUI journeys`.

### Task 12: Fair-test docs + durable corpus seed

**Files:**
- Modify: `app/dogfood/dogfood-app-guide.md` (Manifest section — USER language: what the tab shows, what Promote/Export do, when buttons disable; NO spec/internals leakage)
- Create: `hack/dogfood/journeys/manifest-gui.json` — 3-journey seed corpus (smoke tier): open-tab-in-sync, seeded-drift-promote (core step), managed-ahead-export. Validated by the schema test fixtures pattern; the acceptance run's final journey set replaces/extends this file at sprint end.
- Modify: `hack/dogfood/gui/smoke.sh` if needed so it can point at the new corpus (keep its existing default fixture working).

**Steps:**

- [ ] **Step 1:** write the guide section (read the whole file first, match tone; the swarm sees this — user-visible copy only).
- [ ] **Step 2:** author the 3 journeys with citable `expect`s (banner copy from Task 5/6); `python3 -c` schema-validate; run smoke.sh against the corpus with `--fake-model` covering the read path.
- [ ] **Step 3:** pytest + smoke green. Commit: `docs(dogfood): app-guide manifest section + durable GUI manifest corpus`.

### Task 13: Full gates, push, draft PR

**Steps:**

- [ ] **Step 1:** run everything: six workspace gates; app gate (incl. `npm run build`); `python3 -m pytest hack/dogfood`; e2e specs. Fix anything red.
- [ ] **Step 2:** push `worktree-gui-dogfood-sprint`, open a DRAFT PR titled `feat(app+dogfood): GUI manifest surface (diff/promote/export) + GUI dogfood harness reach` with a body covering: product surface, promote extraction parity, harness additions, the acceptance-loop plan; Claude Code attribution trailer.
- [ ] **Step 3:** verify PR checks start (rebase if mergeStateStatus DIRTY).

---

## Post-plan: acceptance loop (orchestrator-driven, not a task)

Per the llm-dogfooding skill, iterate: journey-compiler (GUI modality, coverage targets from spec §6) → `dispatch-swarm.sh` with `DOGFOOD_BASE=origin/worktree-gui-dogfood-sprint` → collect → trajectory-skeptic → fix product/harness findings in this PR → re-run until the skeptic reports zero product bugs and honest decisive coverage. Then update `hack/dogfood/journeys/manifest-gui.json` with the final corpus, run /greploop to Greptile 5/5 + zero unresolved, confirm SonarCloud + all required checks green, and report.
