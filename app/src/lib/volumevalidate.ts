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

/** Size must be a positive integer followed by g, m, G, or M. */
export const isValidVolSize = (s: string) => /^[1-9]\d*[gmGM]$/.test(s);

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
  if (!isValidVolSize(size)) return "Size must be a positive number followed by g or m (e.g. 1g)";
  return null;
}

/** Returns an error string or null. */
export function volPickError(kind: VolumeKind, selectedVolName: string): string | null {
  if (kind !== "existing_persistent") return null;
  if (!selectedVolName) return "Select a volume";
  return null;
}

/** Build the spec string to pass to volumeAttach / CreateOpts.volumes. */
export function buildVolSpec(r: VolumeRow, freeVolumes: VolumeInfo[]): string {
  const path = r.path.trim();
  const size = r.size.trim();
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
