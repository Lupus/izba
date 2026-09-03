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

/**
 * Strips `/* … *\/` block comments and `//` line comments from source text,
 * shared by both parsers below so a commented-out identifier/case-label is
 * never mistaken for a live one (rather than only stripping on one side).
 *
 * Naive: it does not understand string literals, so a `//` occurring inside
 * a string (e.g. tauri-mock.js's `"http://127.0.0.1:1/"` reply) truncates
 * the rest of that line too. Harmless here — no `case "<label>":` or
 * `generate_handler![...]` identifier this repo cares about shares a line
 * with such a string — but not a general-purpose comment stripper.
 */
function stripComments(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
}

/** Identifiers inside the single `tauri::generate_handler![ ... ]` block. */
export function parseRegisteredCommands(librs: string): string[] {
  const blocks = [...stripComments(librs).matchAll(/generate_handler!\[([\s\S]*?)\]/g)];
  if (blocks.length === 0) throw new Error("no tauri::generate_handler![...] block found in lib.rs");
  if (blocks.length !== 1) {
    throw new Error(`expected exactly one generate_handler![...] block, found ${blocks.length}`);
  }
  return blocks[0][1]
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/** `case "<label>":` string literals, minus the `plugin:…` Tauri-plugin arms. */
export function parseMockedCommands(mockjs: string): string[] {
  const seen = new Set<string>();
  for (const m of stripComments(mockjs).matchAll(/case\s+"([^"]+)"\s*:/g)) {
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
