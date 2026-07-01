import { describe, it, expect } from "vitest";
import bridgeSrc from "../../dogfood/real-bridge.js?raw";

// Load the bridge source and eval its exported pure helper in jsdom.
const SRC = bridgeSrc;

// Minimal types that mirror real-bridge.js's internal state shape.
type EventPayload = { event: string; payload: unknown };
type InvokeLogEntry = { cmd: string; ok: boolean; error: string };
type Pending = { resolve: (v: unknown) => void; reject: (e: Error) => void };
type BridgeState = {
  pending: Map<number, Pending>;
  listeners: Map<string, Set<(p: EventPayload) => void>>;
  invokeLog: InvokeLogEntry[];
  lastCmd: Map<number, string>;
};
type HandleFn = (state: BridgeState, raw: string) => void;

function loadHelper(): HandleFn {
  const mod: { exports?: { __dfHandleMessage: HandleFn } } = {};
  // new Function is the correct tool here: we're loading a plain-JS file
  // (dogfood/real-bridge.js) in a Node/jsdom environment to unit-test its
  // exported pure helper without a bundler. no-new-func is not in the
  // recommended ruleset so no disable directive is needed.
  new Function("module", "window", SRC)(mod, { addEventListener() {}, location: { search: "" } });
  return mod.exports!.__dfHandleMessage;
}

describe("real-bridge protocol", () => {
  it("resolves a pending invoke on an ok reply and logs it", () => {
    const handle = loadHelper();
    let resolved: unknown = null;
    const state: BridgeState = {
      pending: new Map([[1, { resolve: (v: unknown) => { resolved = v; }, reject: () => {} }]]),
      listeners: new Map(),
      invokeLog: [],
      lastCmd: new Map([[1, "list"]]),
    };
    handle(state, JSON.stringify({ id: 1, ok: true, result: [{ name: "web" }] }));
    expect(resolved).toEqual([{ name: "web" }]);
    expect(state.invokeLog).toEqual([{ cmd: "list", ok: true, error: "" }]);
    expect(state.pending.size).toBe(0);
  });

  it("fires event listeners on an event frame", () => {
    const handle = loadHelper();
    let got: unknown = null;
    const state: BridgeState = {
      pending: new Map(),
      listeners: new Map([["create-progress", new Set([(p: EventPayload) => { got = p; }])]]),
      invokeLog: [],
      lastCmd: new Map(),
    };
    handle(state, JSON.stringify({ type: "event", event: "create-progress", payload: "pulling" }));
    expect(got).toEqual({ event: "create-progress", payload: "pulling" });
  });

  it("rejects a pending invoke on an error reply and logs it", async () => {
    const handle = loadHelper();
    let rejectFn!: (e: Error) => void;
    const rejectionPromise = new Promise<void>((_resolve, reject) => {
      rejectFn = reject;
    });
    const state: BridgeState = {
      pending: new Map([[2, { resolve: () => {}, reject: rejectFn }]]),
      listeners: new Map(),
      invokeLog: [],
      lastCmd: new Map([[2, "sandbox-create"]]),
    };
    handle(state, JSON.stringify({ id: 2, ok: false, error: "boom" }));
    // synchronous checks: state cleaned up, log written
    expect(state.invokeLog).toEqual([{ cmd: "sandbox-create", ok: false, error: "boom" }]);
    expect(state.pending.size).toBe(0);
    // the promise stored in pending should have been rejected
    await expect(rejectionPromise).rejects.toThrow("boom");
  });
});
