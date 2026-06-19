import { describe, it, expect } from "vitest";
import { allowKeys } from "../lib/policy";
import { WEB_DEFAULT_PORTS } from "../lib/ports";
import type { AllowEntry } from "../lib/types";

describe("allowKeys", () => {
  it("bare-host string → web default ports", () => {
    expect(allowKeys(["a.com"])).toEqual(new Set(["a.com:80", "a.com:443"]));
  });

  it("scoped entry with explicit ports", () => {
    expect(allowKeys([{ host: "db", ports: [5432] }])).toEqual(new Set(["db:5432"]));
  });

  it("scoped entry WITHOUT ports (backend serializes Option::None) → web defaults, no crash", () => {
    // The Rust backend omits `ports` when it equals the web defaults
    // (set_host_access stores None). The frontend must treat that as the
    // web defaults, not crash with `e.ports is not iterable`.
    const entry = { host: "pypi.org", access: "read" } as unknown as AllowEntry;
    expect(allowKeys([entry])).toEqual(
      new Set(WEB_DEFAULT_PORTS.map((p) => `pypi.org:${p}`)),
    );
  });
});
