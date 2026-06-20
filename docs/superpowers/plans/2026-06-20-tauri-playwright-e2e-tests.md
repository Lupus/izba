# Tauri Playwright E2E Tests — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Playwright end-to-end UI tests for the izba Tauri app that exercise full user journeys against an in-page mock of the Tauri IPC bridge (no `izbad`, no VMMs), runnable on Linux + Windows CI.

**Architecture:** Playwright drives the real React UI served by `vite preview`. A self-contained vanilla-JS init script reimplements `@tauri-apps/api/mocks` `mockIPC` (overwriting `window.__TAURI_INTERNALS__` `invoke`+`transformCallback`), adds an event-listener registry, and a command dispatcher driven by a per-test scenario object. A Node-side `MockHandle` proxy fires backend→frontend events and reads recorded calls via `page.evaluate`.

**Tech Stack:** Playwright `@playwright/test`, TypeScript, Vite, React 18, Tauri 2 (`@tauri-apps/api` v2).

## Global Constraints

- Target app dir: `app/` (Tauri GUI, **excluded from the cargo workspace**).
- No production-source changes — the mock is entirely in `app/e2e/**`.
- Mock must mirror the Rust `FakeDaemon::default` seed: sandboxes `web` (running, `ubuntu:24.04`) + `db` (stopped, `postgres:16`); daemon status `{ version: "0.3.1", pid: 4242, uptime_ms: 1000, sandbox_count: 2 }`.
- Event payload shapes (verified): `create-progress` → string; `shell-output` → `{ id, data }` (data base64); `shell-exit` → `{ id }`.
- Tauri command names + args are exactly as in `app/src/lib/ipc.ts`.
- Playwright projects: `chromium` + `webkit`.
- All TypeScript must pass the existing `tsc` strict gate; no `any` leaks outside the narrow `window as any` casts in the harness.
- Conventional commits (`test(app): ...` / `ci(app): ...` / `build(app): ...`).
- Do NOT touch `app/src/**` or `app/src-tauri/**` except where a task explicitly says so (none do).

---

## File Structure

- `app/package.json` — add `@playwright/test` devDep + `e2e` / `e2e:ui` scripts (modify).
- `app/playwright.config.ts` — Playwright config: `testDir: e2e`, `webServer` runs `vite preview`, projects chromium+webkit (create).
- `app/e2e/mock/tauri-mock.js` — self-contained in-page Tauri IPC mock (create).
- `app/e2e/mock/scenarios.ts` — typed `Scenario` + `defaultScenario()` builder (create).
- `app/e2e/helpers.ts` — `MockHandle` node-side proxy (create).
- `app/e2e/fixtures.ts` — Playwright fixture wiring scenario+mock+goto (create).
- `app/e2e/*.spec.ts` — one spec per UI surface (create, Tasks 4–13).
- `.github/workflows/app.yml` — add Playwright install + run on both OS (modify).
- `app/.gitignore` (or root) — ignore `playwright-report/`, `test-results/`, `app/dist/` already ignored (modify/verify).
- SonarCloud config — register `app/e2e/**` as tests / exclude from coverage (modify; locate the sonar config file first).

---

### Task 1: Playwright scaffolding (deps, config, scripts)

**Files:**
- Modify: `app/package.json`
- Create: `app/playwright.config.ts`
- Modify/verify: `app/.gitignore`

**Interfaces:**
- Produces: a runnable `npm run e2e` that starts `vite preview` on port 1420 and runs Playwright; projects `chromium`, `webkit`.

- [ ] **Step 1: Add the dev dependency**

```bash
cd app && npm install --save-dev @playwright/test@^1.48.0
```

- [ ] **Step 2: Add npm scripts** to `app/package.json` `"scripts"` (keep existing):

```json
"e2e": "playwright test",
"e2e:ui": "playwright test --ui"
```

- [ ] **Step 3: Create `app/playwright.config.ts`**

```ts
import { defineConfig, devices } from "@playwright/test";

const PORT = 1420;

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [["html", { open: "never" }], ["list"]] : "list",
  use: {
    baseURL: `http://localhost:${PORT}`,
    trace: "on-first-retry",
    screenshot: "only-on-failure",
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "webkit", use: { ...devices["Desktop Safari"] } },
  ],
  webServer: {
    command: "npm run preview -- --port " + PORT + " --strictPort",
    url: `http://localhost:${PORT}`,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
```

- [ ] **Step 4: Ignore Playwright outputs** — ensure `app/.gitignore` contains:

```
playwright-report/
test-results/
```

- [ ] **Step 5: Verify the toolchain installs and config parses**

Run: `cd app && npx playwright test --list`
Expected: exits 0, lists "Total: 0 tests" (no specs yet) — proves config is valid.

- [ ] **Step 6: Commit**

```bash
git add app/package.json app/package-lock.json app/playwright.config.ts app/.gitignore
git commit -m "build(app): scaffold Playwright e2e (config, deps, scripts)"
```

---

### Task 2: The in-page Tauri IPC mock + scenarios + handle + fixture

This is the harness. It is verified end-to-end by Task 3's first spec; this task lands the code + a typecheck.

**Files:**
- Create: `app/e2e/mock/tauri-mock.js`
- Create: `app/e2e/mock/scenarios.ts`
- Create: `app/e2e/helpers.ts`
- Create: `app/e2e/fixtures.ts`

**Interfaces:**
- Produces (consumed by all specs):
  - `Scenario` (interface) + `defaultScenario(): Scenario` from `scenarios.ts`.
  - `test` (extended Playwright test with `scenario` option + `mock` fixture) + `expect` from `fixtures.ts`.
  - `MockHandle` from `helpers.ts` with methods: `calls(): Promise<string[]>`, `lastCreate(): Promise<CreateOpts|undefined>`, `pushCreateProgress(msg): Promise<void>`, `pushShellOutput(id, text): Promise<void>`, `fireShellExit(id): Promise<void>`, `resolveCreate(name): Promise<void>`, `rejectCreate(msg): Promise<void>`, `setScenario(partial): Promise<void>`.
- In-page contract: `window.__IZBA_SCENARIO__` (data) is read by `tauri-mock.js`; `window.__IZBA_MOCK__` exposes `{ calls, lastCreate, fireEvent, pushCreateProgress, pushShellOutput, fireShellExit, resolveCreate, rejectCreate, setScenario }`.
- Recorded call strings (asserted by specs): `start:<name>`, `stop:<name>`, `restart:<name>`, `remove:<name>:<force>`, `create:<name>`, `read_logs:<name>`, `read_netlog:<name>`, `policy_show:<name>`, `policy_allow:<name>:<host>:<port>`, `policy_block:<name>:<host>:<port>`, `policy_set:<name>`, `policy_enable:<name>`, `shell_open:<name>:<id>`, `shell_write:<id>:<data>`, `shell_resize:<id>:<cols>x<rows>`, `shell_close:<id>`.

- [ ] **Step 1: Create `app/e2e/mock/tauri-mock.js`** (plain vanilla JS, NO imports — injected before the app bundle)

```js
// Self-contained in-page Tauri IPC mock for Playwright e2e.
// Injected via page.addInitScript({ path }) AFTER the scenario init script, so
// it runs BEFORE the app bundle. Reimplements @tauri-apps/api/mocks `mockIPC`
// (overwriting __TAURI_INTERNALS__.invoke + transformCallback), adds an
// event-listener registry, and a command dispatcher driven by
// window.__IZBA_SCENARIO__. Exposes window.__IZBA_MOCK__ for the test side.
(function () {
  const internals = (window.__TAURI_INTERNALS__ = window.__TAURI_INTERNALS__ || {});

  // transformCallback: exact behaviour from @tauri-apps/api mocks.ts — register
  // the handler as a global `window._<id>` and return its numeric id.
  internals.transformCallback = function (callback, once) {
    const id = window.crypto.getRandomValues(new Uint32Array(1))[0];
    const prop = "_" + id;
    Object.defineProperty(window, prop, {
      value: function (result) {
        if (once) Reflect.deleteProperty(window, prop);
        return callback && callback(result);
      },
      writable: false,
      configurable: true,
    });
    return id;
  };

  const scenario = window.__IZBA_SCENARIO__ || {};
  const calls = [];
  const listeners = new Map(); // event name -> Set<handler id>
  let deferredCreate = null;

  function err(msg) {
    return Promise.reject(new Error(msg));
  }
  function action() {
    return scenario.failAction
      ? err(scenario.errorMessage || "action failed")
      : Promise.resolve();
  }
  function fireEvent(event, payload) {
    const ids = listeners.get(event);
    if (!ids) return 0;
    let n = 0;
    ids.forEach(function (id) {
      const fn = window["_" + id];
      if (typeof fn === "function") {
        fn({ event: event, id: id, payload: payload });
        n++;
      }
    });
    return n;
  }

  internals.invoke = function (cmd, args) {
    args = args || {};
    switch (cmd) {
      case "plugin:event|listen": {
        const set = listeners.get(args.event) || new Set();
        set.add(args.handler);
        listeners.set(args.event, set);
        return Promise.resolve(args.handler);
      }
      case "plugin:event|unlisten": {
        const set = listeners.get(args.event);
        if (set) set.delete(args.eventId);
        return Promise.resolve();
      }
      case "plugin:event|emit":
      case "plugin:event|emit_to":
        return Promise.resolve();

      case "list":
        return scenario.daemonAbsent || scenario.failList
          ? err(scenario.errorMessage || "daemon unreachable")
          : Promise.resolve(scenario.sandboxes || []);
      case "daemon_status":
        return scenario.daemonAbsent || scenario.failStatus
          ? err(scenario.errorMessage || "daemon unreachable")
          : Promise.resolve(scenario.daemonStatus);
      case "version_info":
        return Promise.resolve(scenario.version);

      case "start":
        calls.push("start:" + args.name);
        return action();
      case "stop":
        calls.push("stop:" + args.name);
        return action();
      case "restart":
        calls.push("restart:" + args.name);
        return action();
      case "remove":
        calls.push("remove:" + args.name + ":" + args.force);
        return action();

      case "create": {
        calls.push("create:" + (args.opts && args.opts.name));
        window.__IZBA_LAST_CREATE__ = args.opts;
        if (scenario.createDeferred)
          return new Promise(function (resolve, reject) {
            deferredCreate = { resolve: resolve, reject: reject };
          });
        if (scenario.createError) return err(scenario.createError);
        return Promise.resolve(scenario.createName || (args.opts && args.opts.name));
      }

      case "read_logs":
        calls.push("read_logs:" + args.name);
        return Promise.resolve(scenario.logs || "");
      case "read_netlog":
        calls.push("read_netlog:" + args.name);
        return Promise.resolve(scenario.netlog || []);

      case "policy_show":
        calls.push("policy_show:" + args.name);
        return Promise.resolve(
          (scenario.policy && scenario.policy[args.name]) || { enforcing: false, allow: [] }
        );
      case "policy_allow":
        calls.push("policy_allow:" + args.name + ":" + args.host + ":" + args.port);
        return action();
      case "policy_block":
        calls.push("policy_block:" + args.name + ":" + args.host + ":" + args.port);
        return action();
      case "policy_set":
        calls.push("policy_set:" + args.name);
        return action();
      case "policy_enable":
        calls.push("policy_enable:" + args.name);
        return scenario.failAction
          ? err(scenario.errorMessage || "action failed")
          : Promise.resolve(scenario.policyEnableCount || 0);

      case "shell_open":
        calls.push("shell_open:" + args.name + ":" + args.id);
        return action();
      case "shell_write":
        calls.push("shell_write:" + args.id + ":" + args.data);
        return action();
      case "shell_resize":
        calls.push("shell_resize:" + args.id + ":" + args.cols + "x" + args.rows);
        return action();
      case "shell_close":
        calls.push("shell_close:" + args.id);
        return action();

      default:
        return err("unmocked command: " + cmd);
    }
  };

  window.__IZBA_MOCK__ = {
    calls: function () {
      return calls.slice();
    },
    lastCreate: function () {
      return window.__IZBA_LAST_CREATE__;
    },
    fireEvent: fireEvent,
    pushCreateProgress: function (msg) {
      return fireEvent("create-progress", msg);
    },
    pushShellOutput: function (id, text) {
      // btoa handles ASCII test strings; that is all the specs use.
      return fireEvent("shell-output", { id: id, data: btoa(text) });
    },
    fireShellExit: function (id) {
      return fireEvent("shell-exit", { id: id });
    },
    resolveCreate: function (name) {
      if (deferredCreate) deferredCreate.resolve(name);
    },
    rejectCreate: function (msg) {
      if (deferredCreate) deferredCreate.reject(new Error(msg));
    },
    setScenario: function (partial) {
      Object.assign(scenario, partial);
    },
  };
})();
```

- [ ] **Step 2: Create `app/e2e/mock/scenarios.ts`**

```ts
import type {
  SandboxView,
  DaemonStatusView,
  VersionView,
  BuildInfo,
  CreateOpts,
  EndpointSummary,
  PolicyView,
} from "../../src/lib/types";

export interface Scenario {
  sandboxes: SandboxView[];
  daemonStatus?: DaemonStatusView;
  version?: VersionView;
  logs?: string;
  netlog?: EndpointSummary[];
  policy?: Record<string, PolicyView>;
  failList?: boolean;
  failStatus?: boolean;
  failAction?: boolean;
  daemonAbsent?: boolean;
  errorMessage?: string;
  createName?: string;
  createError?: string;
  createDeferred?: boolean;
  policyEnableCount?: number;
}

function buildInfo(over: Partial<BuildInfo> = {}): BuildInfo {
  return {
    pkg_version: "0.3.1",
    git_describe: "v0.3.1",
    git_sha: "abc1234",
    commit_date: "2026-06-20",
    build_timestamp: "2026-06-20T00:00:00Z",
    rustc: "rustc 1.80.0",
    target: "x86_64-unknown-linux-gnu",
    profile: "release",
    ...over,
  };
}

/** Mirrors the Rust FakeDaemon::default seed. */
export function defaultScenario(): Scenario {
  return {
    sandboxes: [
      { name: "web", image: "ubuntu:24.04", state: { kind: "running" } },
      { name: "db", image: "postgres:16", state: { kind: "stopped" } },
    ],
    daemonStatus: { version: "0.3.1", pid: 4242, uptime_ms: 1000, sandbox_count: 2 },
    version: {
      app: buildInfo(),
      core: buildInfo(),
      daemon: buildInfo(),
      proto: 1,
      mismatch: false,
    },
    logs: "boot ok\nlogin:\n",
    netlog: [],
    policy: {},
  };
}

export type { CreateOpts };
```

- [ ] **Step 3: Create `app/e2e/helpers.ts`**

```ts
import type { Page } from "@playwright/test";
import type { Scenario, CreateOpts } from "./mock/scenarios";

/** Node-side proxy over the in-page window.__IZBA_MOCK__ control surface. */
export class MockHandle {
  constructor(private page: Page) {}

  calls(): Promise<string[]> {
    return this.page.evaluate(() => (window as any).__IZBA_MOCK__.calls());
  }
  lastCreate(): Promise<CreateOpts | undefined> {
    return this.page.evaluate(() => (window as any).__IZBA_MOCK__.lastCreate());
  }
  pushCreateProgress(msg: string): Promise<void> {
    return this.page.evaluate((m) => (window as any).__IZBA_MOCK__.pushCreateProgress(m), msg);
  }
  pushShellOutput(id: string, text: string): Promise<void> {
    return this.page.evaluate(
      ([i, t]) => (window as any).__IZBA_MOCK__.pushShellOutput(i, t),
      [id, text] as const,
    );
  }
  fireShellExit(id: string): Promise<void> {
    return this.page.evaluate((i) => (window as any).__IZBA_MOCK__.fireShellExit(i), id);
  }
  resolveCreate(name: string): Promise<void> {
    return this.page.evaluate((n) => (window as any).__IZBA_MOCK__.resolveCreate(n), name);
  }
  rejectCreate(msg: string): Promise<void> {
    return this.page.evaluate((m) => (window as any).__IZBA_MOCK__.rejectCreate(m), msg);
  }
  setScenario(partial: Partial<Scenario>): Promise<void> {
    return this.page.evaluate((p) => (window as any).__IZBA_MOCK__.setScenario(p), partial);
  }
}
```

- [ ] **Step 4: Create `app/e2e/fixtures.ts`**

```ts
import { test as base, expect } from "@playwright/test";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { defaultScenario, type Scenario } from "./mock/scenarios";
import { MockHandle } from "./helpers";

const HERE = dirname(fileURLToPath(import.meta.url));
const MOCK_PATH = resolve(HERE, "mock/tauri-mock.js");

type Fixtures = {
  /** Override per file/test with test.use({ scenario: {...} }). */
  scenario: Scenario;
  /** Installed mock; navigates to "/" before the test body runs. */
  mock: MockHandle;
};

export const test = base.extend<Fixtures>({
  scenario: [defaultScenario(), { option: true }],
  mock: async ({ page, scenario }, use) => {
    await page.addInitScript((s) => {
      (window as any).__IZBA_SCENARIO__ = s;
    }, scenario);
    await page.addInitScript({ path: MOCK_PATH });
    await page.goto("/");
    await use(new MockHandle(page));
  },
});

export { expect };
```

- [ ] **Step 5: Typecheck the harness**

Run: `cd app && npx tsc --noEmit -p tsconfig.json`
Expected: exits 0 (note: `.js` mock is not typechecked; the three `.ts` files compile clean).
If `tsconfig.json` `include` excludes `e2e/`, add `"e2e"` to `include` OR rely on Playwright's own transform — confirm `npx playwright test --list` still works after Task 3. If tsc complains about `import.meta`, ensure `module`/`moduleResolution` in tsconfig support it (Vite config uses ESM); if not, the file still runs under Playwright's esbuild loader — prefer NOT changing app tsconfig. If tsc errors only on e2e, scope a separate check rather than weakening the app config.

- [ ] **Step 6: Commit**

```bash
git add app/e2e/mock/tauri-mock.js app/e2e/mock/scenarios.ts app/e2e/helpers.ts app/e2e/fixtures.ts
git commit -m "test(app): in-page Tauri IPC mock harness for Playwright e2e"
```

---

### Task 3: Startup & polling spec (proves the harness)

**Files:**
- Create: `app/e2e/startup.spec.ts`

**Interfaces:**
- Consumes: `test`, `expect` (fixtures.ts), `defaultScenario` (scenarios.ts).

**Before writing:** read `app/src/components/TopBar.tsx`, `app/src/components/Rail.tsx`, `app/src/lib/store.ts` to confirm the rendered text/roles for sandbox names, daemon status, and the version string. Use Playwright role/text queries (`page.getByText`, `getByRole`) matching the actual markup.

- [ ] **Step 1: Write the spec**

```ts
import { test, expect } from "./fixtures";

test.describe("startup & polling", () => {
  test("renders the seeded sandbox list", async ({ page, mock }) => {
    await expect(page.getByText("web")).toBeVisible();
    await expect(page.getByText("db")).toBeVisible();
  });

  test("shows daemon status in the top bar", async ({ page }) => {
    // Adjust matcher to TopBar's actual rendering of version "0.3.1".
    await expect(page.getByText(/0\.3\.1/)).toBeVisible();
  });

  test("polling reflects scenario changes", async ({ page, mock }) => {
    await expect(page.getByText("db")).toBeVisible();
    await mock.setScenario({
      sandboxes: [{ name: "web", image: "ubuntu:24.04", state: { kind: "running" } }],
    });
    // usePolling refreshes every 2s; Playwright auto-waits up to the timeout.
    await expect(page.getByText("db")).toHaveCount(0);
    await expect(page.getByText("web")).toBeVisible();
  });
});
```

- [ ] **Step 2: Run and verify it passes**

Run: `cd app && npm run build && npx playwright test startup --project=chromium`
Expected: 3 passed. (First builds `dist/` so `vite preview` has something to serve.)
If a selector misses, fix it against the real component markup, not by loosening intent.

- [ ] **Step 3: Run on webkit too**

Run: `cd app && npx playwright test startup --project=webkit`
Expected: 3 passed (reuses the built `dist/`).

- [ ] **Step 4: Commit**

```bash
git add app/e2e/startup.spec.ts
git commit -m "test(app): e2e startup & polling spec (harness proof)"
```

---

### Task 4: Daemon error states spec

**Files:**
- Create: `app/e2e/daemon-errors.spec.ts`

**Before writing:** read `app/src/components/TopBar.tsx` (error banner + mismatch warning) and `app/src/lib/store.ts` (how `error` is surfaced from a failing `list`/`daemon_status`).

- [ ] **Step 1: Write the spec**

```ts
import { test, expect } from "./fixtures";

test.describe("daemon error states", () => {
  test.describe("daemon unreachable", () => {
    test.use({
      scenario: {
        sandboxes: [],
        daemonAbsent: true,
        failList: true,
        failStatus: true,
        errorMessage: "daemon unreachable",
      },
    });
    test("surfaces an error banner", async ({ page }) => {
      await expect(page.getByText(/daemon unreachable/i)).toBeVisible();
    });
  });

  test.describe("version mismatch", () => {
    test.use({
      scenario: (() => {
        const s = require("./mock/scenarios").defaultScenario();
        s.version.mismatch = true;
        return s;
      })(),
    });
    test("shows a mismatch warning", async ({ page }) => {
      // Adjust to TopBar/About's actual mismatch copy.
      await expect(page.getByText(/version|mismatch|update/i).first()).toBeVisible();
    });
  });
});
```

Note: prefer importing `defaultScenario` at top (`import { defaultScenario } from "./mock/scenarios";`) and building the mismatch scenario with a helper rather than `require`. Use whichever the repo's ESM config accepts; the importing form is preferred.

- [ ] **Step 2: Run and verify**

Run: `cd app && npx playwright test daemon-errors --project=chromium`
Expected: all passed. Fix selectors against real markup as needed.

- [ ] **Step 3: Commit**

```bash
git add app/e2e/daemon-errors.spec.ts
git commit -m "test(app): e2e daemon error-state spec"
```

---

### Task 5: Rail selection spec

**Files:**
- Create: `app/e2e/rail.spec.ts`

**Before writing:** read `app/src/components/Rail.tsx` + `app/src/components/Detail.tsx` to see how selecting a sandbox updates the detail pane, and the "new" button label/aria.

- [ ] **Step 1: Write the spec**

```ts
import { test, expect } from "./fixtures";

test.describe("rail", () => {
  test("selecting a sandbox shows its detail", async ({ page }) => {
    await page.getByText("db").click();
    // Detail should now reflect "db" (image postgres:16). Adjust to real markup.
    await expect(page.getByText(/postgres:16/)).toBeVisible();
  });

  test("the new button opens the create dialog", async ({ page }) => {
    // Adjust label to Rail's actual new-sandbox control.
    await page.getByRole("button", { name: /new/i }).click();
    await expect(page.getByRole("dialog", { name: /new sandbox/i })).toBeVisible();
  });
});
```

- [ ] **Step 2: Run / fix / verify** — `cd app && npx playwright test rail --project=chromium` → passed.
- [ ] **Step 3: Commit** — `git add app/e2e/rail.spec.ts && git commit -m "test(app): e2e rail selection spec"`

---

### Task 6: New-sandbox create flow spec (create-progress events)

**Files:**
- Create: `app/e2e/new-sandbox.spec.ts`

**Before writing:** confirm against `app/src/components/NewSandbox.tsx` (already known): dialog `role="dialog" aria-label="New sandbox"`; inputs labelled `Name`, `Workspace`, `Image`, `vCPUs`, `Memory (MiB)`, `Disk (GiB)`; `+ Add port` button with `Port N bind/host/guest` aria-labels; the `Create` button (label flips to `Creating…` while busy); progress lines render in a mono box; `error` shows in `.text-warn`.

- [ ] **Step 1: Write the spec**

```ts
import { test, expect } from "./fixtures";

async function openCreate(page) {
  await page.getByRole("button", { name: /new/i }).click();
  return page.getByRole("dialog", { name: /new sandbox/i });
}

test.describe("new sandbox", () => {
  test("submits create with the entered options", async ({ page, mock }) => {
    const dlg = await openCreate(page);
    await dlg.getByLabel("Name").fill("api");
    await dlg.getByLabel("Workspace").fill("/home/u/api");
    await dlg.getByLabel("Image").fill("node:22");
    await dlg.getByRole("button", { name: /^create$/i }).click();
    await expect.poll(() => mock.calls()).toContain("create:api");
    const opts = await mock.lastCreate();
    expect(opts).toMatchObject({ name: "api", workspace: "/home/u/api", image: "node:22" });
  });

  test("streams create-progress into the dialog", async ({ page, mock }) => {
    await mock.setScenario({ createDeferred: true }); // hold create open
    const dlg = await openCreate(page);
    await dlg.getByLabel("Name").fill("api");
    await dlg.getByLabel("Workspace").fill("/home/u/api");
    await dlg.getByRole("button", { name: /^create$|creating/i }).click();
    await mock.pushCreateProgress("pulling image");
    await mock.pushCreateProgress("booting");
    await expect(dlg.getByText("pulling image")).toBeVisible();
    await expect(dlg.getByText("booting")).toBeVisible();
    await mock.resolveCreate("api"); // dialog closes, "api" selected
    await expect(page.getByRole("dialog", { name: /new sandbox/i })).toHaveCount(0);
  });

  test("surfaces a create error", async ({ page, mock }) => {
    await mock.setScenario({ createError: "image not found" });
    const dlg = await openCreate(page);
    await dlg.getByLabel("Name").fill("api");
    await dlg.getByLabel("Workspace").fill("/home/u/api");
    await dlg.getByRole("button", { name: /^create$/i }).click();
    await expect(dlg.getByText(/image not found/)).toBeVisible();
  });
});
```

Note on `setScenario` timing: `setScenario` mutates the in-page scenario object the dispatcher reads on each invoke, so calling it after `goto` (i.e. inside the test) takes effect for the subsequent `create` call. Verify this holds; if a test needs the flag set before any app code runs, use `test.use({ scenario })` instead.

- [ ] **Step 2: Run / fix / verify** — `cd app && npx playwright test new-sandbox --project=chromium` → passed.
- [ ] **Step 3: Commit** — `git add app/e2e/new-sandbox.spec.ts && git commit -m "test(app): e2e new-sandbox create+progress spec"`

---

### Task 7: Overview actions spec (start/stop/restart/remove)

**Files:**
- Create: `app/e2e/overview-actions.spec.ts`

**Before writing:** read `app/src/components/Detail.tsx` + `app/src/components/ConfirmDialog.tsx` for the action button labels, which actions apply to running vs stopped sandboxes, the remove-confirm flow, and how a degraded `reason` is shown.

- [ ] **Step 1: Write the spec**

```ts
import { test, expect } from "./fixtures";

test.describe("overview actions", () => {
  test("stop calls stop for the running sandbox", async ({ page, mock }) => {
    await page.getByText("web").click();
    await page.getByRole("button", { name: /^stop$/i }).click();
    await expect.poll(() => mock.calls()).toContain("stop:web");
  });

  test("start calls start for the stopped sandbox", async ({ page, mock }) => {
    await page.getByText("db").click();
    await page.getByRole("button", { name: /^start$/i }).click();
    await expect.poll(() => mock.calls()).toContain("start:db");
  });

  test("remove asks for confirmation then calls remove", async ({ page, mock }) => {
    await page.getByText("db").click();
    await page.getByRole("button", { name: /^remove$|^delete$/i }).click();
    // ConfirmDialog: click the confirming button (adjust label).
    await page.getByRole("button", { name: /^remove$|^delete$|confirm/i }).last().click();
    await expect.poll(() => mock.calls()).toEqual(
      expect.arrayContaining([expect.stringMatching(/^remove:db:/)]),
    );
  });

  test.describe("degraded state", () => {
    test.use({
      scenario: {
        sandboxes: [
          { name: "web", image: "ubuntu:24.04", state: { kind: "degraded", reason: "vm exited" } },
        ],
        daemonStatus: { version: "0.3.1", pid: 4242, uptime_ms: 1000, sandbox_count: 1 },
      },
    });
    test("shows the degraded reason", async ({ page }) => {
      await page.getByText("web").click();
      await expect(page.getByText(/vm exited/)).toBeVisible();
    });
  });
});
```

- [ ] **Step 2: Run / fix / verify** — `cd app && npx playwright test overview-actions --project=chromium` → passed.
- [ ] **Step 3: Commit** — `git add app/e2e/overview-actions.spec.ts && git commit -m "test(app): e2e overview actions spec"`

---

### Task 8: Logs spec

**Files:**
- Create: `app/e2e/logs.spec.ts`

**Before writing:** read `app/src/components/Detail.tsx` (tab switching) + `app/src/components/LogsView.tsx` for the Logs tab control and how `read_logs` output renders.

- [ ] **Step 1: Write the spec**

```ts
import { test, expect } from "./fixtures";

test.describe("logs", () => {
  test.use({
    scenario: (() => {
      const s = require("./mock/scenarios").defaultScenario();
      s.logs = "boot ok\nready on tty\n";
      return s;
    })(),
  });
  test("shows console output in the logs tab", async ({ page, mock }) => {
    await page.getByText("web").click();
    await page.getByRole("tab", { name: /logs/i }).click();
    await expect.poll(() => mock.calls()).toContain("read_logs:web");
    await expect(page.getByText(/ready on tty/)).toBeVisible();
  });
});
```

(Prefer top-level `import { defaultScenario }` over `require` if the ESM config allows; see Task 4 note.)

- [ ] **Step 2: Run / fix / verify** — `cd app && npx playwright test logs --project=chromium` → passed.
- [ ] **Step 3: Commit** — `git add app/e2e/logs.spec.ts && git commit -m "test(app): e2e logs spec"`

---

### Task 9: Netlog spec

**Files:**
- Create: `app/e2e/netlog.spec.ts`

**Before writing:** read `app/src/components/NetlogView.tsx` for column rendering of `EndpointSummary` (host, port, tier, verdict).

- [ ] **Step 1: Write the spec**

```ts
import { test, expect } from "./fixtures";
import { defaultScenario } from "./mock/scenarios";

const s = defaultScenario();
s.netlog = [
  {
    host: "github.com",
    dest_ip: "140.82.112.3",
    port: 443,
    tier: "l7",
    verdict: "allow",
    allow_count: 5,
    deny_count: 0,
    first_seen_ms: 1000,
    last_seen_ms: 2000,
    last_method: "GET",
    last_path: "/",
  },
  {
    host: null,
    dest_ip: "10.0.0.9",
    port: 22,
    tier: "l3",
    verdict: "deny",
    allow_count: 0,
    deny_count: 3,
    first_seen_ms: 1000,
    last_seen_ms: 2000,
    last_method: null,
    last_path: null,
  },
];

test.describe("netlog", () => {
  test.use({ scenario: s });
  test("renders endpoint summaries with tier and verdict", async ({ page, mock }) => {
    await page.getByText("web").click();
    await page.getByRole("tab", { name: /netlog|network|traffic/i }).click();
    await expect.poll(() => mock.calls()).toContain("read_netlog:web");
    await expect(page.getByText("github.com")).toBeVisible();
    await expect(page.getByText(/allow/i).first()).toBeVisible();
    await expect(page.getByText(/deny/i).first()).toBeVisible();
  });
});
```

- [ ] **Step 2: Run / fix / verify** — `cd app && npx playwright test netlog --project=chromium` → passed.
- [ ] **Step 3: Commit** — `git add app/e2e/netlog.spec.ts && git commit -m "test(app): e2e netlog spec"`

---

### Task 10: Policy editor spec

**Files:**
- Create: `app/e2e/policy.spec.ts`

**Before writing:** read `app/src/components/PolicyEditor.tsx` + `app/src/components/FirewallStatus.tsx` for the enforcing badge, the allow/block inputs, and the enable-from-traffic control.

- [ ] **Step 1: Write the spec**

```ts
import { test, expect } from "./fixtures";
import { defaultScenario } from "./mock/scenarios";

const s = defaultScenario();
s.policy = { web: { enforcing: true, allow: ["github.com", { host: "api.x.com", ports: [443] }] } };

test.describe("policy editor", () => {
  test.use({ scenario: s });

  test("shows the policy and enforcing state", async ({ page, mock }) => {
    await page.getByText("web").click();
    await page.getByRole("tab", { name: /policy|firewall/i }).click();
    await expect.poll(() => mock.calls()).toContain("policy_show:web");
    await expect(page.getByText("github.com")).toBeVisible();
    await expect(page.getByText(/enforc/i)).toBeVisible();
  });

  test("allowing a host calls policy_allow", async ({ page, mock }) => {
    await page.getByText("web").click();
    await page.getByRole("tab", { name: /policy|firewall/i }).click();
    // Adjust to the editor's actual add-host inputs + button.
    await page.getByPlaceholder(/host/i).fill("example.com");
    await page.getByPlaceholder(/port/i).fill("443");
    await page.getByRole("button", { name: /allow|add/i }).click();
    await expect.poll(() => mock.calls()).toContain("policy_allow:web:example.com:443");
  });
});
```

- [ ] **Step 2: Run / fix / verify** — `cd app && npx playwright test policy --project=chromium` → passed.
- [ ] **Step 3: Commit** — `git add app/e2e/policy.spec.ts && git commit -m "test(app): e2e policy editor spec"`

---

### Task 11: Shell spec (shell-output / shell-exit events, xterm)

**Files:**
- Create: `app/e2e/shell.spec.ts`

**Before writing:** read `app/src/components/ShellPanel.tsx` + `app/src/lib/shellStore.ts` for: the Shell tab control, how a session id is minted and `shell_open` is invoked, how typed input maps to `shell_write`, how `resize` fires, multi-session tabs, and the close control. xterm's DOM renderer puts text into `.xterm-rows`; assert there (or via `page.locator(".xterm")`). If the session id is random, capture it from `mock.calls()` (the `shell_open:<name>:<id>` entry) and reuse it for `pushShellOutput`.

- [ ] **Step 1: Write the spec**

```ts
import { test, expect } from "./fixtures";

async function openShell(page, mock) {
  await page.getByText("web").click();
  await page.getByRole("tab", { name: /shell|terminal/i }).click();
  const open = await expect
    .poll(async () => (await mock.calls()).find((c) => c.startsWith("shell_open:web:")))
    .not.toBeUndefined()
    .then(async () => (await mock.calls()).find((c) => c.startsWith("shell_open:web:"))!);
  const id = open.split(":")[2];
  return id;
}

test.describe("shell", () => {
  test("opens a session and renders streamed output", async ({ page, mock }) => {
    const id = await openShell(page, mock);
    await mock.pushShellOutput(id, "hello-from-guest\r\n");
    await expect(page.locator(".xterm-rows")).toContainText("hello-from-guest");
  });

  test("typing sends shell_write", async ({ page, mock }) => {
    const id = await openShell(page, mock);
    await page.locator(".xterm-helper-textarea").focus();
    await page.keyboard.type("ls");
    await expect.poll(() => mock.calls()).toEqual(
      expect.arrayContaining([expect.stringMatching(new RegExp(`^shell_write:${id}:`))]),
    );
  });

  test("an exit event marks the session ended", async ({ page, mock }) => {
    const id = await openShell(page, mock);
    await mock.fireShellExit(id);
    await expect(page.getByText(/exit|ended|closed|disconnected/i).first()).toBeVisible();
  });
});
```

The `openShell` helper above is illustrative — simplify to a single `expect.poll` that returns the id once `shell_open:web:` appears. Keep the resize/multi-session/close assertions if `ShellPanel` exposes those controls; drop any that the component does not support (note the drop in the commit message).

- [ ] **Step 2: Run / fix / verify** — `cd app && npx playwright test shell --project=chromium` → passed. xterm timing can need `await expect(...).toContainText` (auto-waits); avoid fixed sleeps.
- [ ] **Step 3: Commit** — `git add app/e2e/shell.spec.ts && git commit -m "test(app): e2e shell session spec"`

---

### Task 12: About dialog spec

**Files:**
- Create: `app/e2e/about.spec.ts`

**Before writing:** read `app/src/components/About.tsx` + `app/src/components/TopBar.tsx` for the about-open control and how app/core/daemon build info renders.

- [ ] **Step 1: Write the spec**

```ts
import { test, expect } from "./fixtures";

test.describe("about", () => {
  test("opens and shows version info", async ({ page }) => {
    await page.getByRole("button", { name: /about/i }).click();
    await expect(page.getByText(/0\.3\.1/).first()).toBeVisible();
    // git sha from defaultScenario buildInfo:
    await expect(page.getByText(/abc1234/).first()).toBeVisible();
  });
});
```

- [ ] **Step 2: Run / fix / verify** — `cd app && npx playwright test about --project=chromium` → passed.
- [ ] **Step 3: Commit** — `git add app/e2e/about.spec.ts && git commit -m "test(app): e2e about dialog spec"`

---

### Task 13: Full local green + CI wiring + SonarCloud

**Files:**
- Modify: `.github/workflows/app.yml`
- Modify: SonarCloud config (locate first — likely `sonar-project.properties` at repo root, or `sonar` settings in `.github/workflows/coverage.yml`/`e2e.yml`; grep for `sonar.sources`/`sonar.tests`).

- [ ] **Step 1: Run the whole suite locally on both engines**

Run: `cd app && npm run build && npx playwright test`
Expected: all specs pass on chromium + webkit. Fix any flakiness (prefer auto-waiting assertions over sleeps).

- [ ] **Step 2: Inspect `.github/workflows/app.yml`** and add an e2e step to BOTH the linux and windows app jobs, after `npm run build`:

```yaml
      - name: Install Playwright browsers
        working-directory: app
        run: npx playwright install --with-deps ${{ runner.os == 'Windows' && 'chromium' || 'chromium webkit' }}
        shell: bash

      - name: Run Playwright e2e
        working-directory: app
        run: npx playwright test ${{ runner.os == 'Windows' && '--project=chromium' || '' }}
        shell: bash

      - name: Upload Playwright report
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: playwright-report-${{ runner.os }}
          path: app/playwright-report/
          retention-days: 7
```

Match the existing job structure (step names, `working-directory`, cache steps). `--with-deps` needs root on Linux (hosted runners have it); on Windows `--with-deps` is a no-op for chromium. Confirm the build step produced `app/dist/` before the e2e step (the `webServer` runs `vite preview`, which needs `dist/`).

- [ ] **Step 3: SonarCloud — exclude e2e from coverage-on-new-code**

Locate the sonar config (grep `sonar.sources`, `sonar.tests`, `sonar.exclusions` across the repo). Add `app/e2e/**` to `sonar.tests` (so it is scanned as test code, not product code) and to coverage exclusions so it does not trip the "0% coverage on new code" gate. Mirror however the app's vitest/`app/src` paths are already configured. Do NOT introduce hardcoded public IPs in product scope — the documentation-range/test IPs live only in `app/e2e/**` test files (acceptable in test sources).

- [ ] **Step 4: Run the app's existing gates to confirm no regression**

```bash
cd app && npm run build && npm run test
cd src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```
Expected: all green (e2e additions must not break the existing vitest/cargo gates).

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/app.yml <sonar-config-file>
git commit -m "ci(app): run Playwright e2e on linux+windows; scope e2e in SonarCloud"
```

---

## Self-Review

**Spec coverage:** Every design scenario (1–10) maps to a task: startup/polling→T3, daemon errors→T4, rail→T5, new-sandbox+progress→T6, overview actions→T7, logs→T8, netlog→T9, policy→T10, shell→T11, about→T12. Harness (self-contained mockIPC + event registry + scenarios + handle + fixture)→T2. Engine matrix + CI + SonarCloud→T1/T13. No design section is unimplemented.

**Placeholder scan:** Harness code (T2) and config (T1) are complete and concrete. Spec tasks intentionally instruct reading the target component for exact selectors because the plan must not hardcode unverified DOM queries — each provides the full scenario, the exact recorded-call strings to assert, and representative query code. This is a deliberate, bounded lookup (one component per spec), not a TODO.

**Type consistency:** `Scenario` fields used by `tauri-mock.js` (`sandboxes`, `daemonStatus`, `version`, `logs`, `netlog`, `policy`, `failList`, `failStatus`, `failAction`, `daemonAbsent`, `errorMessage`, `createName`, `createError`, `createDeferred`, `policyEnableCount`) match `scenarios.ts`. `MockHandle` method names match `window.__IZBA_MOCK__` keys. Recorded-call strings used in specs match the `calls.push(...)` lines in T2. Event payload shapes match `ipc.ts` + `lib.rs` emit sites.

**Known risk:** `remove` records `remove:<name>:<force>` here, whereas the Rust `FakeDaemon` uses `rm:<name>:<force>` — this is fine because the e2e mock is independent of the Rust fake; specs assert against the e2e mock's own strings. Just keep them consistent within `app/e2e/`.
