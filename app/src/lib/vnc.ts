import type { SandboxDetail } from "./types";

// CREDENTIAL DISCIPLINE: `d.vnc_url` carries the desktop's plaintext password
// in its userinfo (spec 2026-08-09). This module must never log it — it only
// ever hands it back to the caller inside the returned `VncPresentation`.

export type VncPresentation =
  | { kind: "url"; url: string; warnings: string[] }
  | { kind: "not-enabled" }
  | { kind: "not-running" }
  | { kind: "restart-required" };

/** Mirrors the CLI's `url_or_reason` + the two warning helpers
 *  (`crates/izba-cli/src/commands/vnc.rs:188-232`), same precedence:
 *  `vnc_url` presence is checked FIRST — a `vnc off` against an already
 *  running sandbox flips `d.vnc` immediately while the live relay (keyed on
 *  the running desktop, not on config) stays up, so the honest answer is
 *  still its URL, paired with a warning. Only once `vnc_url` is ruled out do
 *  we fall through to not-enabled / not-running / restart-required. */
export function vncPresentation(d: SandboxDetail): VncPresentation {
  if (d.vnc_url !== null) {
    const warnings: string[] = [];
    if (!d.vnc) {
      warnings.push("VNC is disabled in config — this desktop stops at the next restart.");
    }
    if (!d.vnc_running) {
      warnings.push(
        `The desktop is not answering. Guest log: izba exec ${d.name} -- cat /var/log/izba-vnc.log`,
      );
    }
    return { kind: "url", url: d.vnc_url, warnings };
  }
  if (!d.vnc) return { kind: "not-enabled" };
  if (d.status !== "running") return { kind: "not-running" };
  return { kind: "restart-required" };
}
