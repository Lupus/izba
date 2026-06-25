import { describe, it, expect } from "vitest";
import type { VolumeInfo } from "../lib/types";
import type { VolumeRow } from "../lib/volumevalidate";
import {
  freeVolumes,
  isValidVolSize,
  usedExistingNames,
  volSizeError,
} from "../lib/volumevalidate";

const vol = (name: string, referenced_by: string[] = []): VolumeInfo => ({
  name,
  size_bytes: 1073741824,
  actual_bytes: 0,
  referenced_by,
});

const existingRow = (selectedVolName: string): VolumeRow => ({
  kind: "existing_persistent",
  name: "",
  path: "",
  size: "",
  selectedVolName,
});

describe("isValidVolSize", () => {
  it("accepts valid sizes with lowercase suffixes", () => {
    expect(isValidVolSize("1g")).toBe(true);
    expect(isValidVolSize("10g")).toBe(true);
    expect(isValidVolSize("1m")).toBe(true);
    expect(isValidVolSize("512m")).toBe(true);
  });

  it("accepts valid sizes with uppercase suffixes", () => {
    expect(isValidVolSize("1G")).toBe(true);
    expect(isValidVolSize("1M")).toBe(true);
  });

  it("rejects zero size ('0g' and '0m')", () => {
    // Rust parse_size rejects zero — the validator must too.
    expect(isValidVolSize("0g")).toBe(false);
    expect(isValidVolSize("0m")).toBe(false);
    expect(isValidVolSize("0G")).toBe(false);
    expect(isValidVolSize("0M")).toBe(false);
  });

  it("rejects empty string", () => {
    expect(isValidVolSize("")).toBe(false);
  });

  it("rejects number-only (no suffix)", () => {
    expect(isValidVolSize("10")).toBe(false);
  });

  it("rejects invalid suffix", () => {
    expect(isValidVolSize("1x")).toBe(false);
    expect(isValidVolSize("1k")).toBe(false);
  });
});

describe("volSizeError", () => {
  it("returns null for valid size", () => {
    expect(volSizeError("ephemeral", "1g")).toBeNull();
  });

  it("surfaces error for '0g' row", () => {
    const err = volSizeError("ephemeral", "0g");
    expect(err).not.toBeNull();
    // Error message should mention positive number
    expect(err).toMatch(/positive/i);
  });

  it("error message mentions g or m", () => {
    const err = volSizeError("ephemeral", "badval");
    expect(err).toMatch(/g or m/i);
  });

  it("returns null for existing_persistent (no size needed)", () => {
    expect(volSizeError("existing_persistent", "0g")).toBeNull();
  });
});

describe("freeVolumes (existing-volume filtering)", () => {
  const empty = new Set<string>();

  it("excludes volumes referenced by any sandbox (referenced_by non-empty)", () => {
    const all = [vol("archive"), vol("inuse", ["other-sbx"])];
    const result = freeVolumes(all, empty, empty).map((v) => v.name);
    expect(result).toEqual(["archive"]);
    expect(result).not.toContain("inuse");
  });

  it("excludes volumes already seeded on this sandbox", () => {
    const all = [vol("cache"), vol("archive")];
    const seeded = new Set(["cache"]);
    const result = freeVolumes(all, seeded, empty).map((v) => v.name);
    expect(result).toEqual(["archive"]);
    expect(result).not.toContain("cache");
  });

  it("excludes volumes already picked by another inline row (usedNames)", () => {
    const all = [vol("vol1"), vol("vol2")];
    const used = new Set(["vol1"]);
    const result = freeVolumes(all, empty, used).map((v) => v.name);
    expect(result).toEqual(["vol2"]);
    expect(result).not.toContain("vol1");
  });

  it("applies all three exclusions together", () => {
    const all = [vol("free"), vol("ref", ["s"]), vol("seeded"), vol("used")];
    const result = freeVolumes(all, new Set(["seeded"]), new Set(["used"])).map((v) => v.name);
    expect(result).toEqual(["free"]);
  });
});

describe("usedExistingNames", () => {
  it("collects existing_persistent picks from OTHER rows, excluding the current row", () => {
    const rows = [existingRow("vol1"), existingRow("vol2")];
    // For row 1, vol1 (row 0's pick) is used; vol2 (its own pick) is not.
    expect(usedExistingNames(rows, 1)).toEqual(new Set(["vol1"]));
    expect(usedExistingNames(rows, 0)).toEqual(new Set(["vol2"]));
  });

  it("ignores rows that are not existing_persistent and blank picks", () => {
    const rows: VolumeRow[] = [
      { kind: "ephemeral", name: "", path: "/x", size: "1g", selectedVolName: "" },
      existingRow(""), // started but nothing picked yet
      existingRow("picked"),
    ];
    expect(usedExistingNames(rows, 0)).toEqual(new Set(["picked"]));
  });
});
