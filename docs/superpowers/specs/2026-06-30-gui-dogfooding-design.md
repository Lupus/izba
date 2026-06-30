# GUI Dogfooding — design (Tauri app, spec-anchored, agent-browser-driven)

Status: **approved design, pre-implementation** (2026-06-30)
Owner: lupus@oxnull.net
Anchors: the `llm-dogfooding` skill (`.claude/skills/llm-dogfooding/`), the
Phase-2 CLI runner (`hack/dogfood/`), `dogfood.yml`, and the Tauri app
(`app/`). Read those before changing this.

## 1. Goal & non-goals

**Goal.** Extend the existing spec-anchored LLM-dogfooding machinery — today
CLI/daemon only — to drive the **Tauri desktop app** the way a real user would,
at swarm scale, in CI, with the same three-phase pipeline (journey-compiler →
cheap-model swarm → trajectory-skeptic) and the same "LLM proposes, harness
disposes" oracle discipline. Catch the GUI-specific class deterministic tests
miss: *the UI is wired correctly but is wrong, awkward, undiscoverable, or
silently lies about daemon state.*

**Non-goals (first cut).**
- Not a replacement for the existing vitest unit/component tests or the
  Playwright e2e suite (those stay; they test the UI against a mock).
- Not exercising the real WebKitGTK render engine or Tauri's own IPC transport
  (see §3 fidelity gap; covered later by an optional WebDriver smoke).
- Not rich interactive-PTY shell journeys (the `ShellPanel` xterm path is
  stubbed to "open + one command echoes back"; deferred — §10).
- Not comprehensive component coverage on day one — **walking skeleton first**
  (§9), then expand.

This increments **after** the CLI/daemon loop is stable, per the skill's own
"Extending to the UI" guidance.

## 2. Decisions (the load-bearing ones)

| # | Decision | Rationale |
|---|---|---|
| D1 | **Reuse the 3-phase pipeline; swap only Phase-2's action/observation layer.** journey-compiler, trajectory-skeptic, `collect-trajectories.py`, caps/budget/report-only, the OpenRouter model layer, and the daemon-state oracles all stay. | The pipeline's value (fair-test boundary, bidirectional skepticism, deterministic gating) is modality-independent. Only "how the Actor acts and observes" differs CLI vs GUI. |
| D2 | **Fidelity = real React frontend in headless Chromium → real backend → real microVMs.** Not the mock; not the shipped WebKitGTK window. | The mock finds no wiring bugs (defeats dogfooding). The real Tauri window isn't drivable by a CDP/browser tool and is heavy/flaky headless. Chromium-on-real-daemon is the best fidelity/cost point and reuses the app's existing browser-test plumbing. |
| D3 | **Real backend = a headless Rust "bridge sidecar" inside `izba-app` that reuses the app's command/view/daemon logic verbatim.** The browser's `__TAURI_INTERNALS__.invoke` is forwarded over a WebSocket to the sidecar, which maps each IPC command to the same `commands::*_core` / `run_action` body the `#[tauri::command]` shims call, and pushes Tauri events (`create-progress`/`shell-output`/`shell-exit`) back as WS frames. | The app is cleanly seamed: `AppState{ daemon: Box<dyn DaemonApi>, make_daemon, shells }`, with the heavy logic in `commands.rs`/`daemon.rs`/`views.rs` and only thin shims in `lib.rs`. A WS dispatcher re-expresses ~30 thin shims + event plumbing while reusing **all** mapping logic against a real `RealDaemon` → `izba-core` DaemonClient → real VMs. No coupling to Tauri test internals. (`tauri::test` MockRuntime is a future higher-fidelity option — D3-alt.) |
| D4 | **Browser driver = `vercel-labs/agent-browser` (pinned `v0.31.1`), called as a `--json` subprocess.** Not Playwright-Python, not a hand-rolled driver. | Apache-2.0 (matches izba); native Rust binary + daemon over CDP; headless Linux; **pure driver with no embedded LLM loop** (our model/caps/oracles stay); deterministic `@eN` set-of-marks refs with token-budget verbosity knobs (`-i`/`-c`/`-d`); `screenshot --annotate` overlays the same refs. Calling it as a subprocess mirrors exactly how the CLI loop calls `izba`. Deletes the need for a custom ref-tagging/snapshot driver. |
| D5 | **Observation = the accessibility set-of-marks, never screenshots, for the cheap Actor.** Screenshots captured only on failure, for the skeptic (Opus). | Cheap models ground far better on a compact `[role] "name" @ref` list than on pixels; it's cheaper and deterministic to gate. Pixels are a strong-model-only signal. |
| D6 | **Fair-test boundary extends to the UI.** The swarm sees only the rendered UI (a11y marks + visible text) + README + an optional user-facing app guide. Never component names, source, spec, or `data-testid`s. | Same anti-cheating rule as the CLI loop. If the Actor can't find/operate a control from what a user perceives, that *is* the finding (discoverability / a11y), not a reason to help it. |
| D7 | **The bridge is baked into a dedicated dogfood frontend build**, not injected by the driver. `real-bridge.js` is the first `<script>` in the served `index.html`, so it defines `__TAURI_INTERNALS__.invoke` before the app bundle loads. | Driver-agnostic (works whether agent-browser or anything else drives the page), and a clean descendant of the existing in-page `tauri-mock.js` — but talking WS to a real sidecar instead of returning canned scenario data. |
| D8 | **Walking skeleton first** (~5 core journeys end-to-end in CI), prove signal/noise, then expand. | Matches the skill's increment-after-stable guidance; de-risks the new substrate before scaling journey authoring (which would otherwise churn against an unproven harness). |

## 3. Architecture

```
                         ┌─────────────────── CI KVM shard (ubuntu-latest) ───────────────────┐
                         │                                                                     │
  journeys.json ────────►│  run_gui_journeys.py  (the GUI Actor loop; caps/budget/report-only) │
  (modality:"gui")       │        │                                                            │
                         │        │ proposes {click|fill|press|select|read|done}               │
                         │        ▼                                                            │
                         │   agent-browser  --json   ◄── snapshot -i (set-of-marks @eN)        │
                         │        │ (Rust CDP daemon)                                           │
                         │        ▼ drives headless Chromium                                    │
                         │   http://127.0.0.1:PORT  (static server: app/dist + real-bridge.js) │
                         │        │ React UI: __TAURI_INTERNALS__.invoke(cmd,args)              │
                         │        ▼ WebSocket (real-bridge.js)                                  │
                         │   izba-app headless sidecar  (reuses commands_core/daemon/views)     │
                         │        │ DaemonApi = RealDaemon                                      │
                         │        ▼                                                            │
                         │   izbad daemon ──► real microVMs (vmlinux + initramfs, /dev/kvm)     │
                         │                                                                     │
                         │   oracles: daemon state-evidence + reconcile-seq (REUSED)           │
                         │          + UI-vs-daemon differential + console/error-boundary        │
                         │          + silent-failure + DOM-expect + latency  (NEW, GUI)         │
                         └─────────────────────────────────────────────────────────────────────┘
                                          │ trajectory bundle (a11y marks, invoke log,
                                          │ console errors, on-failure annotated screenshot,
                                          ▼ state-evidence)
                         collect-trajectories.py ──► trajectory-skeptic (Opus, privileged) ──► triaged report
```

**Fidelity gap (accepted, documented):** vs the shipped app this skips (a) the
generated `#[tauri::command]` macro glue + Tauri IPC serialization (trivial,
generated), and (b) the WebKitGTK render engine (Chromium instead). Both are
covered later by an optional periodic **tauri-driver WebDriver smoke** against
the real window — out of skeleton scope.

## 4. The GUI Actor loop (`hack/dogfood/gui/run_gui_journeys.py`)

Mirrors `run_journeys.py` structure 1:1 — same caps, same report-only contract,
same per-journey isolation, same trajectory writer — differing only in the
act/observe primitives:

- **Observe.** `agent-browser snapshot -i --json` → parse the set-of-marks into a
  compact list the Actor sees: `[@e2] button "Create sandbox"`, `[@e3] textbox
  "Name"`, `[@e7] tab "Policy"`. Role + accessible name only (fair-test). Trim to
  interactive+named; cap chars; the `-i`/`-c`/`-d` knobs keep tokens bounded.
- **Decide.** The GUI Actor system prompt (a branch in `model.py` or a sibling
  `gui_model.py`) constrains replies to a small JSON vocabulary:
  `{"click":"@e2"}` · `{"fill":"@e3","text":"web"}` · `{"press":"Enter"}` ·
  `{"select":"@e9","option":"..."}` · `{"read":true}` (re-snapshot) ·
  `{"done":true}`. Harness disposes — the model never gets a page handle.
- **Act.** Map the reply to an agent-browser subcommand (`click @e2`,
  `fill @e3 "web"`, `press Enter`, …) run as a `--json` subprocess; then settle
  (`agent-browser wait`/load-state) and re-snapshot.
- **Caps (all mandatory, inherited):** `--max-turns`, `--step-cap`, `--max-usd`,
  `--action-timeout-s`, per-step loop-dedup on `(journey_id, action)`.
- **Lifecycle & isolation.** agent-browser runs its daemon once per shard;
  **per journey** we `open` a fresh page/context and `close` it after, and each
  journey still gets its own short `IZBA_DATA_DIR` + its own sidecar/daemon (the
  ~108-byte `sun_path` short-path rule from izba#71 still applies). One journey's
  browser/daemon state cannot contaminate the next.
- **Report-only.** Any driver/subprocess/model error is logged; the loop never
  raises; a trajectory bundle conforming to the (extended) schema is always
  written; exit 0 regardless of findings.

## 5. The bridge sidecar (`izba-app` headless) + `real-bridge.js`

- **`real-bridge.js`** (in `app/`, served first in the dogfood `index.html`):
  reimplements the `tauri-mock.js` surface — `__TAURI_INTERNALS__.invoke`,
  `transformCallback`, the event listener registry, `__TAURI_EVENT_PLUGIN_
  INTERNALS__.unregisterListener` — but instead of returning canned scenario
  data, it (a) forwards each `invoke(cmd,args)` as a WS request and resolves the
  promise on the WS reply, and (b) on WS event frames, fires the registered
  listeners (so `create-progress`/`shell-output`/`shell-exit` reach the React UI
  exactly as Tauri would deliver them).
- **`src/bin/headless.rs`** in `izba-app`: builds the same `AppState` (real
  `RealDaemon` + `make_daemon` factory + `shells` map) and serves a WS endpoint.
  Each `invoke` command name dispatches to the identical body its
  `#[tauri::command]` shim runs (`commands::list_core(api)`,
  `run_action(state, |api| …)`, the `views` conversions, the shell plumbing).
  Tauri `emit` calls become WS event frames. To reach the crate-internal
  `commands`/`daemon`/`views` items, expose a minimal `pub` headless entry from
  `app_lib` (don't widen more than needed).
- **Why not `tauri::test` MockRuntime (D3-alt):** it would drive the real
  `generate_handler!` set for marginally higher fidelity on the macro glue, but
  capturing emitted events out of MockRuntime is fiddly and couples us to Tauri
  test internals. Revisit as a fidelity bump once the skeleton is proven.

## 6. Oracles

**Reused unchanged (daemon truth is modality-independent):**
- **state-evidence** snapshot at journey end (sandboxes, reconcile, per-sandbox
  policy/audit) — the rubric judge grades outcome from ground truth.
- **reconcile-seq** across actions.

**New, GUI-specific, all deterministic:**
- **UI-vs-daemon differential** *(highest value)* — after the journey, does the
  rendered UI state match the daemon reconcile snapshot? "UI shows running but
  daemon says stopped", or "created sandbox never appears in the list" =
  confirmed bug. Unique to the GUI modality.
- **console / error-boundary** — any uncaught JS error, unhandled promise
  rejection, or React error-boundary trip during the journey (captured via
  `agent-browser`'s console access) = candidate.
- **silent-failure** — an `invoke()` that the sidecar rejected but which produced
  no visible error surface in the next snapshot = candidate (action failed, user
  uninformed).
- **DOM-expect** — the journey `expect` (user-observable text/role) is present in
  the post-journey snapshot.
- **a11y/discoverability** — implicit: a control absent from the marks list (no
  accessible name) that a journey needs = the Actor stalls = finding.
- **latency** — time-to-interactive + action→DOM-settle, reusing the budget
  pattern.

## 7. Phase 1 / Phase 3 / schema changes

- **`schema/journeys.schema.json`**: add optional `modality: "cli" | "gui"`
  (default `"cli"`) per journey; same `intent`/`expect`/`source` contract. One
  journeys file may carry both modalities (the runner selects by modality).
- **`schema/trajectory.schema.json`**: GUI action shape `{kind:
  click|fill|press|select|read, ref?, value?}` and observation shape `{marks,
  console_errors, screenshot_ref?}`, alongside the existing CLI action shape.
- **`journey-compiler`** (Phase 1, Opus, privileged): also emit `modality:"gui"`
  journeys — `intent` as a UI goal in user language, `expect` as DOM-observable,
  laundering all component/source/spec knowledge out.
- **`trajectory-skeptic`** (Phase 3, Opus, privileged): read GUI trajectories
  (marks + invoke log + console errors + on-failure annotated screenshots +
  state-evidence); apply the same bidirectional skepticism — refute reds, audit
  greens for cheating/unverified success.

## 8. CI shape (`dogfood.yml`)

Add a `dogfood-gui` job (or a modality matrix axis) that **reuses** the existing
`kernel` / `initramfs` / runtime-tools jobs and the KVM/AppArmor setup from the
`dogfood` job, plus:

- Build the dogfood frontend: `npm ci` (in `app/`) + a vite build that emits
  `app/dist` with `real-bridge.js` inlined first in `index.html`.
- Build the bridge sidecar: `cargo build --release --bin headless -p izba-app`.
- Install the driver: `npm i -g agent-browser@0.31.1 && agent-browser install
  --with-deps`. **Cache** the Chrome-for-Testing download; **egress-allow** that
  host (or pre-bake it into the runner image). Pin the exact version (Labs /
  pre-1.0 churn). **Never** use the `chat` subcommand / `AI_GATEWAY_API_KEY`.
- Serve `app/dist` on `127.0.0.1:PORT`, start the sidecar, then run
  `run_gui_journeys.py` across the same fixed shard matrix, report-only, upload
  the trajectory bundles (+ on-failure logs/screenshots).
- Same dispatch discipline: `dogfood-run/<feature>` branch, dispatch-only, never
  a PR (the `branches-ignore: ['dogfood-run/**']` guards already exist).

## 9. Walking-skeleton scope (first cut)

Substrate (everything above) + **~5 spec-anchored core journeys**, end-to-end in
CI, each proven by the UI-vs-daemon differential oracle:

1. Create a sandbox (NewSandbox dialog) and see it appear in the list.
2. Start it; the row/detail reflects running (matches daemon).
3. Open a shell, run one command, see output (stubbed PTY — §10).
4. Set/enforce a policy (PolicyEditor/EnforceToggle); daemon policy state
   matches the UI.
5. Stop and remove it (ConfirmDialog); it disappears and the daemon agrees.

Exit criterion for the skeleton: the loop runs green in CI, produces a clean
triaged skeptic report, and signal/noise is legible. **Then** expand journeys to
ports, volumes, netlog, logs, seed, storage, about, and the daemon-absent /
error scenarios.

## 10. Risks & open items

- **Interactive shell fidelity.** The `ShellPanel` xterm over
  `shell-output`/`shell-write`/`shell-resize` events is the fiddliest bridge
  path. Skeleton stubs it to "open + one command echoes back"; rich PTY journeys
  deferred until the event-forwarding WS path is proven.
- **agent-browser Labs churn.** Pre-1.0; pin `v0.31.1`, expect breaking changes
  across minors; flag the rename/archive risk. Engine-provenance
  (Rust-direct-CDP vs Playwright `ariaSnapshot`) is cosmetic for us but verify
  against its lockfile if a pure-CDP footprint is ever required.
- **Token weight.** GUI observations are heavier than CLI stdout; rely on
  `-i`/`-c`/`-d` trimming + char caps to hold `--max-usd`.
- **Harness-in-product-repo coverage.** The sidecar (`headless.rs`) and
  `real-bridge.js` are daemon/IPC glue — not unit-coverable; exclude from the
  coverage gate (precedent: `sonar.coverage.exclusions`) and `#[mutants::skip]`
  the daemon glue with justification. Keep pure helpers (snapshot parsing,
  action mapping, oracle logic) covered + mutation-gated.
- **Sidecar surface widening.** Exposing crate-internal `izba-app` items to the
  headless bin must stay minimal (one `pub` headless entry), not a blanket
  `pub`.

## 11. Component inventory (new vs changed)

**New**
- `hack/dogfood/gui/run_gui_journeys.py` — GUI Actor loop.
- `hack/dogfood/gui/driver.py` — thin `agent-browser --json` subprocess wrapper
  (snapshot parse, action map, lifecycle).
- `hack/dogfood/gui/gui_oracles.py` — UI-vs-daemon differential, console,
  silent-failure, DOM-expect, latency.
- `hack/dogfood/gui/gui_model.py` *(or a branch in `model.py`)* — GUI Actor
  system prompt + reply vocabulary.
- `app/dogfood/real-bridge.js` — in-page WS bridge (descendant of `tauri-mock.js`).
- `app/src-tauri/src/bin/headless.rs` + a minimal `pub` headless entry in
  `app_lib`.

**Changed**
- `hack/dogfood/schema/journeys.schema.json`, `…/trajectory.schema.json` — add
  `modality` + GUI action/observation shapes.
- `.claude/agents/journey-compiler.md`, `…/trajectory-skeptic.md` — GUI modality
  awareness.
- `.github/workflows/dogfood.yml` — `dogfood-gui` job.
- `.claude/skills/llm-dogfooding/references/methodology.md` — replace the
  "Extending to the UI" stub with the real section.
- `.claude/skills/llm-dogfooding/SKILL.md` — quick-ref row for the GUI loop.

## 12. Test strategy (TDD, per repo convention)

- Pure helpers are unit-tested with fakes (no browser, no daemon): snapshot→marks
  parsing, Actor-reply→action mapping, each GUI oracle against fixture
  trajectories, the modality selector. Mirror `test_oracles.py`/`test_runner.py`.
- The `agent-browser` subprocess is faked in unit tests (a `FakeDriver` returning
  scripted snapshots/results), exactly as `FakeModel` fakes the LLM today.
- Real-browser + real-daemon behavior is exercised only in the KVM CI job
  (report-only), never in the host gates.
