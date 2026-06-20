# Tauri Playwright E2E Tests — Design

**Date:** 2026-06-20
**Status:** Approved (design); implementation pending
**Scope:** `app/` (Tauri 2 desktop GUI frontend) + `.github/workflows/app.yml`

## Problem

The izba desktop app (`app/`, Tauri 2 + React 18 + Vite) has good *layer-by-layer*
test coverage but **no full-journey end-to-end UI tests**:

| Layer | Coverage today | Tool |
| --- | --- | --- |
| Rust Tauri commands ↔ `FakeDaemon` | ✅ `commands.rs` (10 tests) | `cargo test` |
| Rust `FakeDaemon` mock itself | ✅ `fake.rs` (8 tests) | `cargo test` |
| `ipc.ts` invoke wrappers | ✅ `ipc.test.ts` (mocked `invoke`) | vitest |
| Individual React components | ✅ 13 component test files | vitest + RTL |
| **Full UI journeys across screens** | ❌ **nothing** | — |

We want a test suite that exercises real UI interactions across whole user
journeys and verifies the app behaves as expected — without spawning real
`izbad`/VMMs. The mock must be per-test configurable so each spec can target a
specific app behaviour (failures, version mismatch, streaming output, etc.).

## Decision summary

- **Driver:** Playwright (Node + browser) against the **real React UI** served by
  `vite preview` (the production build, closest to shipped).
- **Mock:** the Tauri IPC bridge is mocked **entirely in-page**, via a
  **self-contained vanilla-JS init script** that reimplements the ~15 lines of
  `@tauri-apps/api/mocks` `mockIPC` (overwriting `window.__TAURI_INTERNALS__`
  `invoke` + `transformCallback`) plus an event registry and a command dispatcher.
  No Tauri runtime, no `izbad`, no VMMs, no build step for the harness.
- **Engine diversity without platform webviews:** Playwright `projects` =
  `chromium` (≈ WebView2 family) + `webkit` (≈ WebKitGTK/Safari family).
- **CI:** run the suite on both Linux and Windows runners (extending
  `.github/workflows/app.yml`).

### Alternatives considered

1. **Real Tauri binary via WebDriverIO + `tauri-driver`** (drives the actual
   built window incl. the real Rust backend with `FakeDaemon` swapped in by a
   build flag). Highest fidelity, but **not Playwright** (Playwright cannot speak
   W3C WebDriver), `tauri-driver` is Linux+Windows-only and flaky, needs
   `WebKitWebDriver`/`msedgedriver` + `xvfb`. Rejected: high maintenance, the
   user asked for Playwright, and the Rust layer is already covered by cargo tests.
2. **Both (Playwright primary + a thin WDIO smoke suite).** More coverage, two
   stacks to maintain. Deferred — can be added later if Rust-IPC-vs-JS-mock drift
   becomes a real problem.
3. **Mock at an `ipc.ts` test seam gated on a `window` flag** (tiny prod-source
   branch). Rejected in favour of zero production-source changes; the official
   `mockIPC` mechanism handles event streaming fine (see below).

## How the mock works (the crux)

`mockIPC` works by overwriting two functions on `window.__TAURI_INTERNALS__`:

- `transformCallback(cb, once?)` — registers `cb` as a global `window._<id>` and
  returns the numeric `id`.
- `invoke(cmd, args)` — our dispatcher.

The Tauri `event` module is built on top of these. `listen(name, handler)`
internally does:

```js
invoke('plugin:event|listen', { event: name, target, handler: transformCallback(handler) })
```

So **our dispatcher sees `plugin:event|listen`** and can record
`{ event: args.event, id: args.handler }` in an in-page registry. To **fire** an
event from a test, the harness calls `window['_'+id]({ event, id, payload })` for
each registered listener of that name — exactly the path real Tauri uses to
deliver backend→frontend events. This is wholly within `mockIPC`'s own contract;
no extra undocumented internals.

### Verified payload shapes

From `app/src/lib/ipc.ts` and the three `app.emit(...)` sites in
`app/src-tauri/src/lib.rs`:

- `create-progress` → payload is a **string** (the progress message).
- `shell-output` → payload `{ id: string, data: string }` where `data` is
  **base64**; the frontend filters by `id` and base64-decodes.
- `shell-exit` → payload `{ id: string }`; frontend filters by `id`.

## Components

```
app/
  e2e/
    mock/
      tauri-mock.js      # self-contained vanilla JS, injected via addInitScript({ path })
                         #   - installs __TAURI_INTERNALS__.transformCallback (exact mocks.ts impl)
                         #   - installs __TAURI_INTERNALS__.invoke = command dispatcher
                         #   - maintains event-listener registry (plugin:event|listen/unlisten)
                         #   - exposes window.__IZBA_MOCK__ { fireEvent, calls, getScenario }
      scenarios.ts       # typed builders reusing app/src/lib/types.ts
                         #   defaultScenario() mirrors Rust FakeDaemon::default
                         #   (web=running, db=stopped); overrides for failure modes
    fixtures.ts          # Playwright fixture: injects scenario via addInitScript,
                         #   then tauri-mock.js, before navigation; yields { page, mock }
    helpers.ts           # node-side MockHandle proxy over page.evaluate:
                         #   calls(), pushCreateProgress(msg), pushShellOutput(id, text),
                         #   fireShellExit(id), setScenario(partial)
    startup.spec.ts
    daemon-errors.spec.ts
    rail.spec.ts
    new-sandbox.spec.ts
    overview-actions.spec.ts
    logs.spec.ts
    netlog.spec.ts
    policy.spec.ts
    shell.spec.ts
    about.spec.ts
  playwright.config.ts
  package.json           # + @playwright/test; scripts: e2e, e2e:ui
```

### Unit boundaries

- **`tauri-mock.js`** — does one thing: present a faithful in-page Tauri IPC
  surface driven by a plain-data scenario, recording calls and routing events.
  Pure vanilla JS, no imports, no bundling. Depends only on a
  `window.__IZBA_SCENARIO__` object injected before it.
- **`scenarios.ts`** — pure data builders; depends only on `types.ts`. No
  Playwright, no DOM.
- **`helpers.ts` (`MockHandle`)** — the only place that knows how to translate
  test intent (`pushShellOutput`) into `page.evaluate(() => window.__IZBA_MOCK__.fireEvent(...))`.
  Depends on a Playwright `Page`.
- **`fixtures.ts`** — wires the above into a Playwright test fixture; the specs
  depend only on the fixture, never on injection mechanics.
- **specs** — each depends only on the fixture + scenario builders; one user
  surface per file.

## Scenario coverage (full UI interactions)

1. **Startup / polling** (`startup.spec.ts`) — list renders web(running)+db(stopped),
   topbar shows daemon status + version, 2s polling refresh reflects scenario changes.
2. **Daemon error states** (`daemon-errors.spec.ts`) — daemon absent → error
   banner; app↔daemon version mismatch → warning surface.
3. **Rail** (`rail.spec.ts`) — select a sandbox updates Detail; "new" opens the
   create form.
4. **New sandbox** (`new-sandbox.spec.ts`) — fill name/image/cpus/mem/workspace/
   ports → submit asserts `create` args; streamed `create-progress` events render;
   success selects the new sandbox; error path surfaces the failure.
5. **Overview actions** (`overview-actions.spec.ts`) — start/stop/restart/remove
   call the right commands (asserted via `mock.calls()`); remove shows a confirm
   dialog; degraded state shows its reason.
6. **Logs** (`logs.spec.ts`) — `read_logs` output renders in LogsView.
7. **Netlog** (`netlog.spec.ts`) — endpoint summaries render with tier/verdict.
8. **Policy** (`policy.spec.ts`) — `policy_show` renders; allow/block/set/enable
   call the right commands; firewall enforcing badge reflects state.
9. **Shell** (`shell.spec.ts`) — open (`shell_open`), output events render in
   xterm, typing → `shell_write`, resize → `shell_resize`, `shell-exit` event
   marks the session dead, multiple session tabs, close → `shell_close`.
10. **About** (`about.spec.ts`) — version dialog shows app/core/daemon build info.

## Wiring

- **`playwright.config.ts`**
  - `webServer: { command: 'npm run preview', port: 1420, reuseExistingServer: !process.env.CI }`
  - `projects: [{ name: 'chromium', ... }, { name: 'webkit', ... }]`
  - `use: { trace: 'on-first-retry', screenshot: 'only-on-failure' }`
  - `testDir: './e2e'`
- **`package.json`** — add `@playwright/test` (devDependency); scripts
  `"e2e": "playwright test"`, `"e2e:ui": "playwright test --ui"`. `npm run build`
  remains the prerequisite (preview serves `dist/`).
- **CI (`.github/workflows/app.yml`)** — after `npm run build`:
  `npx playwright install --with-deps` then `npm run e2e`. Linux runner:
  chromium + webkit. Windows runner: chromium (webkit-on-Windows optional/skipped).
  Upload Playwright HTML report / traces as artifacts on failure.
- **SonarCloud** — register `app/e2e/**` as test sources and exclude it from
  coverage-on-new-code so the suite does not trip the "0% coverage on new code"
  gate (see the SonarCloud gate note in project memory). vitest remains the
  coverage source; e2e is supplementary. Also avoid Sonar Security-Rating
  trip-wires in test code (no hardcoded external IPs beyond clearly test-only
  documentation-range literals; prefer placeholder hostnames).

## Cross-platform / "consistency" — explicit limitation

The real app uses WebKitGTK (Linux) and WebView2 (Windows) webviews; Playwright
cannot drive those directly (that requires the rejected WebDriver path). "Both
platforms for consistency" therefore means:

- The identical Node+browser suite runs on **both Linux and Windows CI runners**
  (catches frontend-logic regressions identically; validates OS/CI path consistency).
- **chromium + webkit** Playwright projects approximate the two real webview
  engine families without platform webviews.

It does **not** catch true WebView2/WebKitGTK-specific rendering quirks, and does
**not** exercise the Rust Tauri command + event-emit layer (covered by the 18
existing cargo tests). These are accepted tradeoffs of the chosen approach.

## Out of scope (deliberately)

- Real `izbad` / VMM spawning.
- Rust Tauri command handlers, `AppState`, real event emission (cargo tests).
- True webview-engine rendering fidelity.

## Testing strategy for the harness itself

The harness is exercised by the specs that use it (if `tauri-mock.js` mis-routes
an event, the shell/new-sandbox specs fail). No separate unit tests for the
harness beyond that — keeping it small and spec-driven. Existing vitest + cargo
suites stay untouched and complementary.
