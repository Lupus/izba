import type { VolumeInfo } from "./types";

export type VolumeKind = "ephemeral" | "new_persistent" | "existing_persistent";

export interface VolumeRow {
  kind: VolumeKind;
  /** Used for new_persistent. */
  name: string;
  path: string;
  /** Used for ephemeral + new_persistent. */
  size: string;
  /** Used for existing_persistent (the name of the picked volume). */
  selectedVolName: string;
}

export function defaultVolumeRow(): VolumeRow {
  return { kind: "ephemeral", name: "", path: "", size: "", selectedVolName: "" };
}

/** Empty name is allowed (ephemeral); non-empty must be lowercase alphanumeric + _ or -. */
export const isValidVolName = (s: string) => s === "" || /^[a-z0-9][a-z0-9_-]*$/.test(s);

/** Non-empty lowercase alphanumeric name (for new_persistent, where a name is required). */
export const isValidVolNameNonEmpty = (s: string) => /^[a-z0-9][a-z0-9_-]*$/.test(s);

/** Path must start with "/" and contain no commas (commas delimit the CLI spec). */
export const isValidVolPath = (s: string) => s.startsWith("/") && !s.includes(",");

/**
 * Fold a human-typed size into the daemon's canonical `<n>g` / `<n>m` form,
 * or `null` when it is not a size we take.
 *
 * Accepted: a positive whole number (no leading zero) followed by any common
 * spelling of gigabytes or megabytes — `5g`, `5G`, `5GB`, `5gb`, `5 GiB` —
 * with surrounding whitespace. The suffix letters `b`/`ib` are decoration,
 * not a unit change: izba volumes are binary-sized (1 GiB = 2^30) on every
 * path, so `5GB` and `5GiB` are the same request. Kilobytes, bare numbers,
 * and other units are refused so a typo never silently sizes a disk.
 * The Rust side (`izba_core::volume::parse_size`) accepts the same grammar;
 * this normalizer exists so the wire spec stays the canonical form.
 */
export function normalizeVolSize(s: string): string | null {
  const m = /^\s*([1-9]\d*)\s*([gm])(?:i?b)?\s*$/i.exec(s);
  if (!m) return null;
  return `${m[1]}${m[2].toLowerCase()}`;
}

/** True when `normalizeVolSize` accepts the value. */
export const isValidVolSize = (s: string) => normalizeVolSize(s) !== null;

/** A row the user added but left entirely blank is silently ignored on submit. */
export function isBlankVolRow(r: VolumeRow): boolean {
  switch (r.kind) {
    case "ephemeral":
      return !r.path.trim() && !r.size.trim();
    case "new_persistent":
      return !r.name.trim() && !r.path.trim() && !r.size.trim();
    case "existing_persistent":
      return !r.selectedVolName && !r.path.trim();
  }
}

/** A started row is valid only when all required fields validate per kind. */
export function isValidVolRow(r: VolumeRow): boolean {
  switch (r.kind) {
    case "ephemeral":
      return isValidVolPath(r.path.trim()) && isValidVolSize(r.size.trim());
    case "new_persistent":
      return (
        isValidVolNameNonEmpty(r.name.trim()) &&
        isValidVolPath(r.path.trim()) &&
        isValidVolSize(r.size.trim())
      );
    case "existing_persistent":
      return !!r.selectedVolName && isValidVolPath(r.path.trim());
  }
}

/** Returns an error string or null. name is the trimmed value. */
export function volNameError(kind: VolumeKind, name: string): string | null {
  if (kind !== "new_persistent") return null;
  if (!isValidVolNameNonEmpty(name)) return "Name must match [a-z0-9][a-z0-9_-]*";
  return null;
}

/** Returns an error string or null. path is the trimmed value. */
export function volPathError(path: string): string | null {
  if (!isValidVolPath(path)) return "Guest path must be absolute (start with /) and have no commas";
  return null;
}

/** Returns an error string or null. size is the trimmed value. */
export function volSizeError(kind: VolumeKind, size: string): string | null {
  if (kind === "existing_persistent") return null;
  if (!isValidVolSize(size)) return "Size must be a whole number of gigabytes or megabytes, e.g. 5g, 5GB or 512m";
  return null;
}

/** Returns an error string or null. */
export function volPickError(kind: VolumeKind, selectedVolName: string): string | null {
  if (kind !== "existing_persistent") return null;
  if (!selectedVolName) return "Select a volume";
  return null;
}

/**
 * Compute the volumes available to attach as an existing_persistent volume for a
 * given inline row, given the full known volume set and the set of names already
 * spoken for. A volume is free when:
 *   - it is not referenced by any sandbox (`referenced_by` is empty),
 *   - its name is not in `seededNames` (already attached to THIS sandbox), and
 *   - its name is not in `usedNames` (picked by another inline existing row).
 *
 * Pure so the filtering contract is directly unit-testable (the Radix Select's
 * options live in a closed portal and aren't queryable in jsdom).
 */
export function freeVolumes(
  allVolumes: VolumeInfo[],
  seededNames: ReadonlySet<string>,
  usedNames: ReadonlySet<string>,
): VolumeInfo[] {
  return allVolumes.filter(
    (v) =>
      v.referenced_by.length === 0 && !seededNames.has(v.name) && !usedNames.has(v.name),
  );
}

/**
 * The set of existing_persistent volume names picked by inline rows OTHER than
 * `rowIdx` — i.e. names that should be excluded from `rowIdx`'s picker.
 */
export function usedExistingNames(rows: VolumeRow[], rowIdx: number): Set<string> {
  return new Set(
    rows
      .filter((r, i) => i !== rowIdx && r.kind === "existing_persistent")
      .map((r) => r.selectedVolName)
      .filter(Boolean),
  );
}

/** Build the spec string to pass to volumeAttach / CreateOpts.volumes. */
export function buildVolSpec(r: VolumeRow, freeVolumes: VolumeInfo[]): string {
  const path = r.path.trim();
  // Callers gate on isValidVolRow first; an unparseable size falls through
  // verbatim so the daemon's own error surfaces rather than a silent rewrite.
  const size = normalizeVolSize(r.size) ?? r.size.trim();
  switch (r.kind) {
    case "ephemeral":
      return `${path}:${size}`;
    case "new_persistent":
      return `${r.name.trim()}:${path}:${size}`;
    case "existing_persistent": {
      const vol = freeVolumes.find((v) => v.name === r.selectedVolName);
      const sizeMiB = vol ? Math.round(vol.size_bytes / 1048576) : 0;
      return `${r.selectedVolName}:${path}:${sizeMiB}m`;
    }
  }
}
