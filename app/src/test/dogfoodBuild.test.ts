import { describe, it, expect } from "vitest";
import { injectBridge } from "../../dogfood/inject.mjs";

describe("dogfood bridge injection", () => {
  it("inserts real-bridge.js as the first script, before the module bundle", () => {
    const html =
      '<!doctype html><html><head><title>x</title></head>' +
      '<body><script type="module" src="/assets/index-abc.js"></script></body></html>';
    const out = injectBridge(html);
    const bridgeIdx = out.indexOf("/real-bridge.js");
    const bundleIdx = out.indexOf("/assets/index-abc.js");
    expect(bridgeIdx).toBeGreaterThan(-1);
    expect(bridgeIdx).toBeLessThan(bundleIdx);
  });

  it("is idempotent (no double injection)", () => {
    const html = '<head></head><body><script type="module" src="/x.js"></script></body>';
    expect(injectBridge(injectBridge(html))).toBe(injectBridge(html));
  });
});
