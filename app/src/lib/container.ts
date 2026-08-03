/** Human-readable label for the in-guest workload container state token,
 *  mirroring the CLI's `container_label` (crates/izba-cli/src/commands/
 *  status.rs) so the GUI and `izba status` tell the same story. `null`
 *  (stopped sandbox, unreachable guest, or pre-Phase-7 daemon), `"unknown"`,
 *  and any unrecognized token all render as "unknown" — never a healthy
 *  claim. The honest exited/created cases carry a parenthetical so the line
 *  doesn't imply the workload is up when it isn't. */
export function containerLabel(token: string | null): string {
  switch (token) {
    case "running":
      return "running";
    case "stopped":
      return "stopped (workload exited)";
    case "created":
      return "created (not started)";
    case "creating":
      return "creating";
    case "paused":
      return "paused";
    default:
      return "unknown";
  }
}
