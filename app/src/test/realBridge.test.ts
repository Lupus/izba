import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

// Load the bridge source and eval its exported pure helper in jsdom.
const SRC = readFileSync(resolve(__dirname, "../../dogfood/real-bridge.js"), "utf8");

function loadHelper() {
  const mod: any = {};
  // The file ends with: if (typeof module!=='undefined') module.exports={__dfHandleMessage};
  // eslint-disable-next-line no-new-func
  new Function("module", "window", SRC)(mod, { addEventListener() {}, location: { search: "" } });
  return mod.exports.__dfHandleMessage;
}

describe("real-bridge protocol", () => {
  it("resolves a pending invoke on an ok reply and logs it", () => {
    const handle = loadHelper();
    let resolved: any = null;
    const state = {
      pending: new Map([[1, { resolve: (v: any) => (resolved = v), reject: () => {} }]]),
      listeners: new Map(),
      invokeLog: [] as any[],
      lastCmd: new Map([[1, "list"]]),
    };
    handle(state, JSON.stringify({ id: 1, ok: true, result: [{ name: "web" }] }));
    expect(resolved).toEqual([{ name: "web" }]);
    expect(state.invokeLog).toEqual([{ cmd: "list", ok: true, error: "" }]);
    expect(state.pending.size).toBe(0);
  });

  it("fires event listeners on an event frame", () => {
    const handle = loadHelper();
    let got: any = null;
    const state = {
      pending: new Map(),
      listeners: new Map([["create-progress", new Set([(p: any) => (got = p)])]]),
      invokeLog: [],
      lastCmd: new Map(),
    };
    handle(state, JSON.stringify({ type: "event", event: "create-progress", payload: "pulling" }));
    expect(got).toEqual({ event: "create-progress", payload: "pulling" });
  });
});
