/** Binary-unit bytes, one decimal above B (410.0 MiB, 1.2 GiB). */
export function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let v = n;
  let u = 0;
  while (v >= 1024 && u < units.length - 1) {
    v /= 1024;
    u += 1;
  }
  return u === 0 ? `${Math.round(v)} B` : `${v.toFixed(1)} ${units[u]}`;
}

/** Uptime as its two most significant units (2h 14m, 3d 5h, 45s). */
export function formatUptime(ms: number): string {
  const s = Math.floor(ms / 1000);
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s % 60}s`;
  return `${s}s`;
}

/** Meter color class selector: ok < 0.8 ≤ warn < 0.95 ≤ crit. The single
 *  source of the thresholds — every usage bar goes through this. */
export function meterTone(fraction: number): "ok" | "warn" | "crit" {
  if (fraction >= 0.95) return "crit";
  if (fraction >= 0.8) return "warn";
  return "ok";
}
