# Tauri Mock Parity Guard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the desktop app's Playwright IPC mock (`app/e2e/mock/tauri-mock.js`) answer every command registered in `app/src-tauri/src/lib.rs`, and add a CI-gated parity guard so the two can never silently diverge again.

**Architecture:** The guard is a Vitest unit test (`app/src/test/tauriMockParity.test.ts`) that imports both source files via Vite's `?raw` loader (the pattern `realBridge.test.ts` already uses), parses the `generate_handler![...]` list and the mock's `case "..."` labels with small pure functions in `app/src/test/tauriMockParity.ts`, and fails on any registered command with no mock case (and on any stale mock case with no registered command). Both parses are guarded by a plausibility floor so an empty parse can never report parity. The 22 currently-missing commands get canned mock cases in `tauri-mock.js`, driven by new optional fields on the e2e `Scenario` type, and a second unit test (`app/src/test/tauriMock.test.ts`) loads the mock IIFE against a fake `window` and asserts each new case resolves with a plausible shape.

**Tech Stack:** Vitest 4 (jsdom `unit` project, already run by `npm run test` in both App CI jobs), TypeScript, plain ES5-style JS for the mock (it is injected into the page before the bundle, so it must stay self-contained and not use imports).

**Spec:** GitHub issue #275 — https://github.com/Lupus/izba/issues/275 (Acceptance Criteria are the contract; counts measured against `origin/main` at `3774ca5a`).

## Global Constraints

- All app work happens under `app/`; run `npm` commands from `app/`.
- No product/behaviour change in `app/src-tauri` or `izba-core` (issue Out of Scope).
- No new Playwright specs (issue Out of Scope) — the new unit tests exercise the mock directly.
- The mock file `app/e2e/mock/tauri-mock.js` is a self-contained IIFE injected via `page.addInitScript`; keep it dependency-free, `var`/`function`-style consistent with the existing code, and keep the `default: return err("unmocked command: " + cmd)` fall-through.
- `eslint` ignores `e2e/`, but `src/**` is linted with `--max-warnings 0` and typechecked by `tsc` (`npm run build`); new files under `src/test/` must pass both.
- Coverage config excludes `src/test/**`, so helper modules placed there neither need nor get coverage.
- Conventional commits; every commit body ends with `Refs #275`.
- Gate before every commit (from `app/`): `npm run lint && npm run build && npm run test`. Do not run the Playwright e2e locally unless browsers are already installed; CI runs it.
- Observed fact the issue text gets slightly wrong: the mock ALREADY handles `shell_open`/`shell_write`/`shell_resize`/`shell_close`. The allowlist of intentionally-unmocked commands is therefore EMPTY today; it must still exist as an explicit, documented constant.

---

### Task 1: Mock cases for the 22 missing commands, driven by a behaviour test

**Files:**
- Modify: `app/e2e/mock/tauri-mock.js` (add cases after the `policy_set` case at ~line 172, before the `shell_open` case; plus USB/volume/port/stats cases after `vnc_proxy_stop` ~line 215)
- Modify: `app/e2e/mock/scenarios.ts:12-30` (extend `Scenario` with optional fields for the new canned data)
- Create: `app/src/test/tauriMock.test.ts`

**Interfaces:**
- Consumes: the existing mock control surface (`scenario.failAction`, `scenario.errorMessage`, `calls`, `action()`, `err()`).
- Produces: new optional `Scenario` fields read live by the mock:
  - `stats?: Record<string, SandboxStats>` — `stats` answers `scenario.stats[name]`, else a canned stopped snapshot.
  - `ports?: Record<string, PortRule[]>` — `port_list` answers `scenario.ports[name]`, else `[]`.
  - `volumes?: VolumeInfo[]` — `volume_list` answers it, else `[]`.
  - `usbUpstream?: UsbUpstream | null` — `usb_upstream_show` answers it, else `null` (feature off).
  - `usbDevices?: UsbDevice[]` — `usb_list_devices` answers it, else `[]`.
  - `usbStatus?: Record<string, UsbStatus>` — `usb_status` answers `scenario.usbStatus[name]`, else `{ grants: [], restart_required: false }`.
  - Every mutating command pushes a `"<cmd>:<args…>"` string onto `calls` and returns `action()` (so `failAction` rejects it), except `volume_prune`, which resolves `{ removed: [], reclaimed_bytes: 0 }` on success.
- Task 2's guard relies on every new case being written as a literal `case "<command>":` label on its own line inside the `switch (cmd)`.

- [ ] **Step 1: Write the failing behaviour test**

Create `app/src/test/tauriMock.test.ts`:

```ts
import { describe, it, expect } from "vitest";
import mockSrc from "../../e2e/mock/tauri-mock.js?raw";

// tauri-mock.js is a self-contained IIFE that installs itself on `window`.
// Evaluating it with a fresh plain object as `window` gives each test an
// isolated mock with its own scenario and calls log — no jsdom globals
// leak between tests. Same new Function technique as realBridge.test.ts.
type Invoke = (cmd: string, args?: Record<string, unknown>) => Promise<unknown>;
type MockWindow = {
  __IZBA_SCENARIO__?: Record<string, unknown>;
  __TAURI_INTERNALS__?: { invoke: Invoke };
  __IZBA_MOCK__?: { calls(): string[] };
};

function loadMock(scenario: Record<string, unknown> = {}) {
  const w: MockWindow = { __IZBA_SCENARIO__: scenario };
  new Function("window", mockSrc)(w);
  return { invoke: w.__TAURI_INTERNALS__!.invoke, calls: () => w.__IZBA_MOCK__!.calls() };
}

describe("tauri-mock: policy commands", () => {
  it("answers the git/full/enforce/add-endpoints verbs and logs the call", async () => {
    const m = loadMock();
    await expect(m.invoke("policy_git_allow", { name: "web", target: "github.com/o/r", write: true })).resolves.toBeUndefined();
    await expect(m.invoke("policy_git_revoke", { name: "web", target: "github.com/o/r" })).resolves.toBeUndefined();
    await expect(m.invoke("policy_add_endpoints", { name: "web", entries: [{ kind: "http", host: "a", port: 443, access: "read" }], enforce: true })).resolves.toBeUndefined();
    await expect(m.invoke("policy_set_full", { name: "web", allow: [], git: [] })).resolves.toBeUndefined();
    await expect(m.invoke("policy_set_enforce", { name: "web", on: true })).resolves.toBeUndefined();
    expect(m.calls()).toEqual([
      "policy_git_allow:web:github.com/o/r:true",
      "policy_git_revoke:web:github.com/o/r",
      "policy_add_endpoints:web:1:true",
      "policy_set_full:web",
      "policy_set_enforce:web:true",
    ]);
  });

  it("rejects mutations under failAction with the scenario's message", async () => {
    const m = loadMock({ failAction: true, errorMessage: "nope" });
    await expect(m.invoke("policy_set_enforce", { name: "web", on: true })).rejects.toThrow("nope");
  });
});

describe("tauri-mock: stats", () => {
  it("answers a canned stopped snapshot when the scenario has none", async () => {
    const m = loadMock();
    const s = (await m.invoke("stats", { name: "web" })) as { name: string; running: boolean; disk: unknown; guest: unknown };
    expect(s.name).toBe("web");
    expect(s.running).toBe(false);
    expect(s.guest).toBeNull();
    expect(s.disk).toEqual({ rw_img_bytes: 0, volumes: [], logs_bytes: 0, image_bytes: 0 });
  });

  it("prefers the scenario's per-sandbox stats", async () => {
    const snap = { name: "web", running: true, uptime_ms: 5, host: null, disk: { rw_img_bytes: 1, volumes: [], logs_bytes: 0, image_bytes: 0 }, guest: null };
    const m = loadMock({ stats: { web: snap } });
    await expect(m.invoke("stats", { name: "web" })).resolves.toEqual(snap);
  });
});

describe("tauri-mock: ports", () => {
  it("lists from the scenario and logs publish/unpublish with the frontend's camelCase args", async () => {
    const rule = { bind: "127.0.0.1", host_port: 8080, guest_port: 80 };
    const m = loadMock({ ports: { web: [rule] } });
    await expect(m.invoke("port_list", { name: "web" })).resolves.toEqual([rule]);
    await expect(m.invoke("port_list", { name: "db" })).resolves.toEqual([]);
    await expect(m.invoke("port_publish", { name: "web", ruleSpec: "8080:80", persist: true })).resolves.toBeUndefined();
    await expect(m.invoke("port_unpublish", { name: "web", bind: "127.0.0.1", hostPort: 8080 })).resolves.toBeUndefined();
    expect(m.calls()).toEqual(["port_publish:web:8080:80:true", "port_unpublish:web:127.0.0.1:8080"]);
  });
});

describe("tauri-mock: volumes", () => {
  it("lists, attaches, detaches, removes and prunes", async () => {
    const vol = { name: "data", size_bytes: 10, actual_bytes: 5, referenced_by: ["web"] };
    const m = loadMock({ volumes: [vol] });
    await expect(m.invoke("volume_list")).resolves.toEqual([vol]);
    await expect(m.invoke("volume_attach", { name: "web", spec: "data:/data" })).resolves.toBeUndefined();
    await expect(m.invoke("volume_detach", { name: "web", guestPath: "/data" })).resolves.toBeUndefined();
    await expect(m.invoke("volume_remove", { name: "data" })).resolves.toBeUndefined();
    await expect(m.invoke("volume_prune")).resolves.toEqual({ removed: [], reclaimed_bytes: 0 });
    expect(m.calls()).toEqual([
      "volume_attach:web:data:/data",
      "volume_detach:web:/data",
      "volume_remove:data",
      "volume_prune",
    ]);
  });

  it("volume_list defaults to empty and volume_prune honours failAction", async () => {
    const m = loadMock({ failAction: true });
    await expect(m.invoke("volume_list")).resolves.toEqual([]);
    await expect(m.invoke("volume_prune")).rejects.toThrow("action failed");
  });
});

describe("tauri-mock: usb", () => {
  it("reports the feature off by default and empty inventory/status", async () => {
    const m = loadMock();
    await expect(m.invoke("usb_upstream_show")).resolves.toBeNull();
    await expect(m.invoke("usb_list_devices")).resolves.toEqual([]);
    await expect(m.invoke("usb_status", { name: "web" })).resolves.toEqual({ grants: [], restart_required: false });
  });

  it("answers from the scenario when configured", async () => {
    const upstream = { host: "127.0.0.1", port: 3240, resolved: "127.0.0.1", trust: "own-host-loopback", warning: null };
    const dev = { busid: "3-2", device: "0403:6001", description: "FT232", shared: true, granted_to: [], attached_to: null, bind_command: null };
    const status = { grants: [{ device: "0403:6001", busid_pin: "3-2", description: "FT232", granted_at_unix_ms: 1, attached: false }], restart_required: true };
    const m = loadMock({ usbUpstream: upstream, usbDevices: [dev], usbStatus: { web: status } });
    await expect(m.invoke("usb_upstream_show")).resolves.toEqual(upstream);
    await expect(m.invoke("usb_list_devices")).resolves.toEqual([dev]);
    await expect(m.invoke("usb_status", { name: "web" })).resolves.toEqual(status);
  });

  it("logs the mutating verbs with the frontend's camelCase args", async () => {
    const m = loadMock();
    await expect(m.invoke("usb_upstream_set", { host: "h", port: 3240, allowRemote: false })).resolves.toBeUndefined();
    await expect(m.invoke("usb_allow", { name: "web", device: "0403:6001", busidPin: "3-2" })).resolves.toBeUndefined();
    await expect(m.invoke("usb_revoke", { name: "web", device: "0403:6001" })).resolves.toBeUndefined();
    await expect(m.invoke("usb_attach", { name: "web", device: "0403:6001" })).resolves.toBeUndefined();
    await expect(m.invoke("usb_detach", { name: "web", device: "0403:6001" })).resolves.toBeUndefined();
    expect(m.calls()).toEqual([
      "usb_upstream_set:h:3240:false",
      "usb_allow:web:0403:6001:3-2",
      "usb_revoke:web:0403:6001",
      "usb_attach:web:0403:6001",
      "usb_detach:web:0403:6001",
    ]);
  });
});

describe("tauri-mock: fall-through", () => {
  it("still rejects a genuinely unknown command loudly", async () => {
    const m = loadMock();
    await expect(m.invoke("no_such_cmd")).rejects.toThrow("unmocked command: no_such_cmd");
  });
});
```

- [ ] **Step 2: Run it to verify it fails**

Run (from `app/`): `npx vitest run --project=unit src/test/tauriMock.test.ts`
Expected: FAIL — every describe except "fall-through" rejects with `unmocked command: <cmd>`.

- [ ] **Step 3: Extend the `Scenario` type**

In `app/e2e/mock/scenarios.ts`, extend the type import and the interface:

```ts
import type {
  SandboxView,
  SandboxDetail,
  DaemonStatusView,
  VersionView,
  BuildInfo,
  CreateOpts,
  EndpointSummary,
  PolicyView,
  SandboxStats,
  PortRule,
  VolumeInfo,
  UsbUpstream,
  UsbDevice,
  UsbStatus,
} from "../../src/lib/types";
```

and add, after `details?:` inside `interface Scenario`:

```ts
  /** `stats` responses keyed by sandbox name; a sandbox with no entry gets
   *  a canned stopped snapshot. */
  stats?: Record<string, SandboxStats>;
  /** `port_list` responses keyed by sandbox name (default `[]`). */
  ports?: Record<string, PortRule[]>;
  /** `volume_list` response (default `[]`). */
  volumes?: VolumeInfo[];
  /** `usb_upstream_show` response; `null`/absent = USB feature off. */
  usbUpstream?: UsbUpstream | null;
  /** `usb_list_devices` response (default `[]`). */
  usbDevices?: UsbDevice[];
  /** `usb_status` responses keyed by sandbox name (default: no grants). */
  usbStatus?: Record<string, UsbStatus>;
```

- [ ] **Step 4: Add the mock cases**

In `app/e2e/mock/tauri-mock.js`, insert after the `policy_set` case (the `return action();` at line ~172, before `case "shell_open":`):

```js
      case "policy_add_endpoints":
        calls.push(
          "policy_add_endpoints:" + args.name + ":" + (args.entries || []).length + ":" + args.enforce
        );
        return action();
      case "policy_set_full":
        calls.push("policy_set_full:" + args.name);
        return action();
      case "policy_set_enforce":
        calls.push("policy_set_enforce:" + args.name + ":" + args.on);
        return action();
      case "policy_git_allow":
        calls.push("policy_git_allow:" + args.name + ":" + args.target + ":" + args.write);
        return action();
      case "policy_git_revoke":
        calls.push("policy_git_revoke:" + args.name + ":" + args.target);
        return action();
```

and insert after the `vnc_proxy_stop` case (before the `// Manifest diff/export/promote.` comment):

```js
      // Stats / ports / volumes / USB. Read-side commands answer from the
      // scenario (see Scenario in scenarios.ts) with inert defaults; write-side
      // commands log their frontend-shaped (camelCase) args and go through
      // action() so failAction rejects them like every other mutation.
      case "stats":
        calls.push("stats:" + args.name);
        return Promise.resolve(
          (scenario.stats && scenario.stats[args.name]) || {
            name: args.name,
            running: false,
            uptime_ms: null,
            host: null,
            disk: { rw_img_bytes: 0, volumes: [], logs_bytes: 0, image_bytes: 0 },
            guest: null,
          }
        );

      case "port_list":
        calls.push("port_list:" + args.name);
        return Promise.resolve((scenario.ports && scenario.ports[args.name]) || []);
      case "port_publish":
        calls.push("port_publish:" + args.name + ":" + args.ruleSpec + ":" + args.persist);
        return action();
      case "port_unpublish":
        calls.push("port_unpublish:" + args.name + ":" + args.bind + ":" + args.hostPort);
        return action();

      case "volume_list":
        calls.push("volume_list");
        return Promise.resolve(scenario.volumes || []);
      case "volume_attach":
        calls.push("volume_attach:" + args.name + ":" + args.spec);
        return action();
      case "volume_detach":
        calls.push("volume_detach:" + args.name + ":" + args.guestPath);
        return action();
      case "volume_remove":
        calls.push("volume_remove:" + args.name);
        return action();
      case "volume_prune":
        calls.push("volume_prune");
        return scenario.failAction
          ? err(scenario.errorMessage || "action failed")
          : Promise.resolve({ removed: [], reclaimed_bytes: 0 });

      case "usb_upstream_show":
        calls.push("usb_upstream_show");
        return Promise.resolve(scenario.usbUpstream || null);
      case "usb_upstream_set":
        calls.push("usb_upstream_set:" + args.host + ":" + args.port + ":" + args.allowRemote);
        return action();
      case "usb_list_devices":
        calls.push("usb_list_devices");
        return Promise.resolve(scenario.usbDevices || []);
      case "usb_status":
        calls.push("usb_status:" + args.name);
        return Promise.resolve(
          (scenario.usbStatus && scenario.usbStatus[args.name]) || {
            grants: [],
            restart_required: false,
          }
        );
      case "usb_allow":
        calls.push("usb_allow:" + args.name + ":" + args.device + ":" + args.busidPin);
        return action();
      case "usb_revoke":
        calls.push("usb_revoke:" + args.name + ":" + args.device);
        return action();
      case "usb_attach":
        calls.push("usb_attach:" + args.name + ":" + args.device);
        return action();
      case "usb_detach":
        calls.push("usb_detach:" + args.name + ":" + args.device);
        return action();
```

Note: the behaviour test's `calls()` expectations for the read-side verbs are NOT asserted (the ports/volumes/usb tests only assert the mutating entries), so if `calls()` in those tests picks up `port_list:web` etc. entries, adjust the test expectations to filter: replace `expect(m.calls()).toEqual([...])` in the ports/volumes/usb describes with `expect(m.calls().filter((c) => !/^(port_list|volume_list|usb_upstream_show|usb_list_devices|usb_status)/.test(c))).toEqual([...])`. Prefer the filter over dropping the read-side `calls.push` — the existing read-side cases (`inspect`, `read_logs`, `policy_show`) all log, and specs rely on that style.

- [ ] **Step 5: Run the test to verify it passes**

Run: `npx vitest run --project=unit src/test/tauriMock.test.ts`
Expected: PASS, all describes green.

- [ ] **Step 6: Run the full gate**

Run (from `app/`): `npm run lint && npm run build && npm run test`
Expected: lint clean, tsc clean, all unit + browser tests pass.

- [ ] **Step 7: Commit**

```bash
git add app/e2e/mock/tauri-mock.js app/e2e/mock/scenarios.ts app/src/test/tauriMock.test.ts
git commit -m "test(app): mock the 22 registered commands the Playwright IPC shim skipped

policy (git allow/revoke, add_endpoints, set_full, set_enforce), USB (8),
volumes (5), ports (3) and stats had no case in e2e/mock/tauri-mock.js, so
any spec reaching those views hit 'unmocked command' instead of the flow
under test. Each new case answers from the Scenario (new optional
stats/ports/volumes/usb* fields) with inert defaults, or logs its
frontend-shaped args and goes through action(). tauriMock.test.ts loads
the IIFE against a fake window and pins the shapes.

Refs #275"
```

---

### Task 2: Parity guard between `generate_handler![]` and the mock's `case` labels

**Files:**
- Create: `app/src/test/tauriMockParity.ts` (pure parse/compare helpers)
- Create: `app/src/test/tauriMockParity.test.ts` (synthetic tests + the real-file guard)
- Modify: `CLAUDE.md` (the `app/src-tauri` bullet in the Crate map: one sentence pointing at the guard)

**Interfaces:**
- Consumes: Task 1's mock cases (every registered command now has a literal `case "<cmd>":` label).
- Produces (in `tauriMockParity.ts`):
  - `parseRegisteredCommands(librs: string): string[]` — the identifiers inside the single `tauri::generate_handler![ ... ]` block, in source order; throws if the block is absent or appears more than once.
  - `parseMockedCommands(mockjs: string): string[]` — every `case "<label>":` string literal inside the file, excluding labels containing `:` (the `plugin:event|…` Tauri-plugin arms), in source order, de-duplicated.
  - `INTENTIONALLY_UNMOCKED: readonly string[]` — the documented allowlist. EMPTY today.
  - `MIN_PLAUSIBLE_COMMANDS = 30` — plausibility floor for each side.
  - `compareCommandSets(registered: string[], mocked: string[], allowlist: readonly string[]): { missing: string[]; stale: string[] }` — `missing` = registered − mocked − allowlist; `stale` = mocked − registered. Throws `RangeError` if either input has fewer than `MIN_PLAUSIBLE_COMMANDS` entries.

- [ ] **Step 1: Write the failing synthetic tests**

Create `app/src/test/tauriMockParity.test.ts`:

```ts
import { describe, it, expect } from "vitest";
import librs from "../../src-tauri/src/lib.rs?raw";
import mockjs from "../../e2e/mock/tauri-mock.js?raw";
import {
  INTENTIONALLY_UNMOCKED,
  MIN_PLAUSIBLE_COMMANDS,
  compareCommandSets,
  parseMockedCommands,
  parseRegisteredCommands,
} from "./tauriMockParity";

const many = (prefix: string, n: number) => Array.from({ length: n }, (_, i) => `${prefix}${i}`);

describe("parseRegisteredCommands", () => {
  it("extracts the identifiers inside generate_handler![...] in order", () => {
    const src = `
      fn run() {
        tauri::Builder::default()
          .invoke_handler(tauri::generate_handler![
            list,
            daemon_status, // trailing comment
            stats
          ])
      }`;
    expect(parseRegisteredCommands(src)).toEqual(["list", "daemon_status", "stats"]);
  });

  it("throws when the block is absent", () => {
    expect(() => parseRegisteredCommands("fn main() {}")).toThrow(/generate_handler/);
  });

  it("throws when the block appears more than once", () => {
    const one = "tauri::generate_handler![a, b]";
    expect(() => parseRegisteredCommands(one + "\n" + one)).toThrow(/exactly one/);
  });
});

describe("parseMockedCommands", () => {
  it("extracts case labels and skips the plugin:event arms", () => {
    const src = `
      switch (cmd) {
        case "plugin:event|listen": { return 1; }
        case "plugin:event|emit":
        case "plugin:event|emit_to":
          return 2;
        case "list":
          return 3;
        case "start":
        case "stop":
          return 4;
        default:
          return 0;
      }`;
    expect(parseMockedCommands(src)).toEqual(["list", "start", "stop"]);
  });

  it("de-duplicates a label that appears twice", () => {
    expect(parseMockedCommands('case "a": case "a": case "b":')).toEqual(["a", "b"]);
  });
});

describe("compareCommandSets", () => {
  const base = many("cmd_", MIN_PLAUSIBLE_COMMANDS);

  it("reports a registered command with no mock case as missing", () => {
    const { missing, stale } = compareCommandSets([...base, "usb_attach"], base, []);
    expect(missing).toEqual(["usb_attach"]);
    expect(stale).toEqual([]);
  });

  it("reports a mock case with no registered command as stale", () => {
    const { missing, stale } = compareCommandSets(base, [...base, "policy_enable"], []);
    expect(missing).toEqual([]);
    expect(stale).toEqual(["policy_enable"]);
  });

  it("excuses an allowlisted command from the missing set", () => {
    const { missing } = compareCommandSets([...base, "shell_open"], base, ["shell_open"]);
    expect(missing).toEqual([]);
  });

  it("refuses to compare an implausibly small registered side", () => {
    expect(() => compareCommandSets([], base, [])).toThrow(RangeError);
    expect(() => compareCommandSets(many("x", MIN_PLAUSIBLE_COMMANDS - 1), base, [])).toThrow(RangeError);
  });

  it("refuses to compare an implausibly small mocked side", () => {
    expect(() => compareCommandSets(base, [], [])).toThrow(RangeError);
  });
});

describe("parity guard: lib.rs generate_handler![] vs e2e/mock/tauri-mock.js", () => {
  const registered = parseRegisteredCommands(librs);
  const mocked = parseMockedCommands(mockjs);

  it("parses a plausible number of commands on each side", () => {
    // If either of these trips, the PARSER regressed (or the app really lost
    // most of its commands) — fix the parser, do not lower the floor to pass.
    expect(registered.length).toBeGreaterThanOrEqual(MIN_PLAUSIBLE_COMMANDS);
    expect(mocked.length).toBeGreaterThanOrEqual(MIN_PLAUSIBLE_COMMANDS);
  });

  it("every allowlist entry names a real registered command", () => {
    for (const cmd of INTENTIONALLY_UNMOCKED) expect(registered).toContain(cmd);
  });

  it("every registered command has a mock case (or is explicitly allowlisted)", () => {
    const { missing } = compareCommandSets(registered, mocked, INTENTIONALLY_UNMOCKED);
    expect(
      missing,
      `registered in app/src-tauri/src/lib.rs but unmocked in app/e2e/mock/tauri-mock.js: ${missing.join(", ")}\n` +
        "Add a `case \"<cmd>\":` to the mock, or add the command to INTENTIONALLY_UNMOCKED with a reason.",
    ).toEqual([]);
  });

  it("every mock case answers a command the app still registers", () => {
    const { stale } = compareCommandSets(registered, mocked, INTENTIONALLY_UNMOCKED);
    expect(
      stale,
      `mocked in app/e2e/mock/tauri-mock.js but no longer registered in app/src-tauri/src/lib.rs: ${stale.join(", ")}`,
    ).toEqual([]);
  });
});
```

- [ ] **Step 2: Run it to verify it fails**

Run (from `app/`): `npx vitest run --project=unit src/test/tauriMockParity.test.ts`
Expected: FAIL — cannot resolve `./tauriMockParity` (module does not exist yet).

- [ ] **Step 3: Write the helpers**

Create `app/src/test/tauriMockParity.ts`:

```ts
// Parity between the Tauri command set the desktop app registers
// (app/src-tauri/src/lib.rs, `tauri::generate_handler![...]`) and the case
// labels the Playwright IPC mock answers (app/e2e/mock/tauri-mock.js).
//
// The two lists are hand-maintained in different languages, so nothing else
// ties them together: adding a `#[tauri::command]` without a mock case used
// to shrink e2e reach silently (issue #275). tauriMockParity.test.ts turns
// that into a red `npm run test`, which both App CI jobs run.

/**
 * Commands that are registered but deliberately have NO mock case.
 *
 * Empty on purpose: every registered command, including the four `shell_*`
 * verbs, has a case in tauri-mock.js today. Add an entry here — with a
 * comment saying why the Playwright suite must never reach it — rather than
 * letting a gap exist by omission. The guard also checks each entry names a
 * real registered command, so a stale allowlist entry fails too.
 */
export const INTENTIONALLY_UNMOCKED: readonly string[] = [];

/**
 * Floor below which a parse is treated as broken rather than as "few
 * commands". lib.rs registers 47 commands at the time of writing; a parser
 * that finds 0 on both sides would otherwise report perfect parity.
 */
export const MIN_PLAUSIBLE_COMMANDS = 30;

/** Identifiers inside the single `tauri::generate_handler![ ... ]` block. */
export function parseRegisteredCommands(librs: string): string[] {
  const blocks = [...librs.matchAll(/generate_handler!\[([\s\S]*?)\]/g)];
  if (blocks.length === 0) throw new Error("no tauri::generate_handler![...] block found in lib.rs");
  if (blocks.length !== 1) {
    throw new Error(`expected exactly one generate_handler![...] block, found ${blocks.length}`);
  }
  return blocks[0][1]
    .replace(/\/\/[^\n]*/g, "") // strip line comments
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/** `case "<label>":` string literals, minus the `plugin:…` Tauri-plugin arms. */
export function parseMockedCommands(mockjs: string): string[] {
  const seen = new Set<string>();
  for (const m of mockjs.matchAll(/case\s+"([^"]+)"\s*:/g)) {
    const label = m[1];
    if (label.includes(":")) continue; // plugin:event|listen etc.
    seen.add(label);
  }
  return [...seen];
}

/**
 * `missing`: registered but neither mocked nor allowlisted.
 * `stale`: mocked but no longer registered.
 * Throws RangeError when either side is implausibly small, so a parser
 * regression can never report parity.
 */
export function compareCommandSets(
  registered: string[],
  mocked: string[],
  allowlist: readonly string[],
): { missing: string[]; stale: string[] } {
  if (registered.length < MIN_PLAUSIBLE_COMMANDS) {
    throw new RangeError(
      `only ${registered.length} registered commands parsed (floor ${MIN_PLAUSIBLE_COMMANDS}); parser broken?`,
    );
  }
  if (mocked.length < MIN_PLAUSIBLE_COMMANDS) {
    throw new RangeError(
      `only ${mocked.length} mocked commands parsed (floor ${MIN_PLAUSIBLE_COMMANDS}); parser broken?`,
    );
  }
  const mockedSet = new Set(mocked);
  const registeredSet = new Set(registered);
  const excused = new Set(allowlist);
  return {
    missing: registered.filter((c) => !mockedSet.has(c) && !excused.has(c)),
    stale: mocked.filter((c) => !registeredSet.has(c)),
  };
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run --project=unit src/test/tauriMockParity.test.ts`
Expected: PASS. If the real-file guard reports `missing`, Task 1 left a command out — fix the mock, not the guard. If it reports `stale`, a mock case names a command lib.rs does not register — remove that case.

- [ ] **Step 5: Prove the guard bites (throwaway, do not commit)**

Temporarily comment out the `usb_detach` case in `app/e2e/mock/tauri-mock.js`, re-run the guard, and confirm the failure message names `usb_detach`. Then `git checkout -- app/e2e/mock/tauri-mock.js` to restore it (`git diff --stat` must show the mock unchanged afterwards).

- [ ] **Step 6: Document the contract in CLAUDE.md**

In `CLAUDE.md`, inside the `app/src-tauri` bullet of the Crate map (the paragraph that ends with the `cd app && npm ci && npm run build && …` gate), append this sentence after that gate command line:

```
  Every command in `generate_handler![…]` must also have a `case` in the
  Playwright IPC mock `app/e2e/mock/tauri-mock.js` — `app/src/test/
  tauriMockParity.test.ts` (part of `npm run test`) fails on a registered
  command with no mock case, on a stale mock case, and on a parse that finds
  implausibly few commands; deliberate exclusions go in its
  `INTENTIONALLY_UNMOCKED` list with a reason (empty today).
```

- [ ] **Step 7: Run the full gate**

Run (from `app/`): `npm run lint && npm run build && npm run test`
Expected: all green.

- [ ] **Step 8: Commit**

```bash
git add app/src/test/tauriMockParity.ts app/src/test/tauriMockParity.test.ts CLAUDE.md
git commit -m "test(app): guard generate_handler![] against the Playwright mock's case list

A registered #[tauri::command] with no case in e2e/mock/tauri-mock.js used
to shrink e2e reach silently (22 of 47 commands were unmocked). The guard
parses both sides, fails on a missing or stale case, refuses to compare
when either parse finds fewer than MIN_PLAUSIBLE_COMMANDS entries (so an
empty parse cannot report parity), and keeps intentional exclusions in an
explicit, documented INTENTIONALLY_UNMOCKED list — empty today, since the
shell_* verbs are already mocked. Runs under npm run test in both App CI
jobs.

Refs #275"
```

---

## Self-review against the issue's Acceptance Criteria

| AC | Task |
| --- | --- |
| Guard compares `generate_handler![]` vs mock case labels, fails on registered-but-unmocked not in allowlist | Task 2 (`compareCommandSets.missing`, real-file guard test) |
| Guard fails on zero / implausibly low parse count | Task 2 (`MIN_PLAUSIBLE_COMMANDS`, `RangeError`, plus the explicit floor test) |
| Allowlist explicit and documented in source | Task 2 (`INTENTIONALLY_UNMOCKED`, doc comment; empty because `shell_*` are already mocked — noted) |
| Mock gains working cases for the 22 named commands | Task 1 (behaviour test pins every one) |
| Guard passes on `origin/main` HEAD with 47 registered | Task 2 Step 4 |
| Guard runs in CI | `npm run test` is a step in both `app.yml` jobs; no workflow change needed |

Extra beyond the letter of the ACs, within the issue's spirit (INVEST notes cite the stale `policy_enable` case): the guard also reports stale mock cases.
