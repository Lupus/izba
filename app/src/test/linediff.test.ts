import { describe, it, expect } from "vitest";
import { diffLines } from "../lib/linediff";

describe("diffLines", () => {
  it("marks identical inputs as unchanged rows", () => {
    const rows = diffLines("a\nb", "a\nb");
    expect(rows).toEqual([
      { from: "a", to: "a", changed: false },
      { from: "b", to: "b", changed: false },
    ]);
  });

  it("pairs a changed line into one row with both sides highlighted", () => {
    const rows = diffLines("cpus: 2", "cpus: 4");
    expect(rows).toEqual([{ from: "cpus: 2", to: "cpus: 4", changed: true }]);
  });

  it("keeps common context and isolates an inserted line", () => {
    // The egress case from the field report: one added allow-list entry in an
    // otherwise identical YAML block must highlight ONLY the added line.
    const from = "enforce: true\nallow:\n- host: a.com\n";
    const to = "enforce: true\nallow:\n- host: a.com\n- host: b.com\n";
    const rows = diffLines(from, to);
    expect(rows).toEqual([
      { from: "enforce: true", to: "enforce: true", changed: false },
      { from: "allow:", to: "allow:", changed: false },
      { from: "- host: a.com", to: "- host: a.com", changed: false },
      { from: null, to: "- host: b.com", changed: true },
    ]);
  });

  it("isolates a removed line", () => {
    const rows = diffLines("a\nb\nc", "a\nc");
    expect(rows).toEqual([
      { from: "a", to: "a", changed: false },
      { from: "b", to: null, changed: true },
      { from: "c", to: "c", changed: false },
    ]);
  });

  it("pairs unequal-length change runs row-wise", () => {
    const rows = diffLines("x\ny", "z");
    expect(rows).toEqual([
      { from: "x", to: "z", changed: true },
      { from: "y", to: null, changed: true },
    ]);
  });

  it("treats a trailing newline as insignificant (serde_yaml emits one)", () => {
    expect(diffLines("a\n", "a")).toEqual([{ from: "a", to: "a", changed: false }]);
  });

  it("handles empty sides", () => {
    expect(diffLines("", "")).toEqual([]);
    expect(diffLines("", "a")).toEqual([{ from: null, to: "a", changed: true }]);
    expect(diffLines("a", "")).toEqual([{ from: "a", to: null, changed: true }]);
  });
});
