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
