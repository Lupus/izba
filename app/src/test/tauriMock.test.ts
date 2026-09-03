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

// The read-side verbs (port_list, volume_list, usb_upstream_show,
// usb_list_devices, usb_status) log to `calls` just like inspect/read_logs,
// but the ports/volumes/usb describes below only assert the mutating
// entries — filter the read-side noise out before comparing.
function mutatingCalls(calls: string[]): string[] {
  return calls.filter(
    (c) => !/^(port_list|volume_list|usb_upstream_show|usb_list_devices|usb_status)/.test(c)
  );
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
    expect(mutatingCalls(m.calls())).toEqual(["port_publish:web:8080:80:true", "port_unpublish:web:127.0.0.1:8080"]);
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
    expect(mutatingCalls(m.calls())).toEqual([
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
    expect(mutatingCalls(m.calls())).toEqual([
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
