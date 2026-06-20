import { describe, it, expect } from "vitest";
import { isValidVolSize, volSizeError } from "../lib/volumevalidate";

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
