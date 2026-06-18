export interface VolumeRow {
  name: string;
  path: string;
  size: string;
}

/** Empty name is allowed (ephemeral); non-empty must be lowercase alphanumeric + _ or -. */
export const isValidVolName = (s: string) => s === "" || /^[a-z0-9][a-z0-9_-]*$/.test(s);

/** Path must start with "/" and contain no commas (commas delimit the CLI spec). */
export const isValidVolPath = (s: string) => s.startsWith("/") && !s.includes(",");

/** Size must be a positive integer followed by g, m, G, or M. */
export const isValidVolSize = (s: string) => /^\d+[gmGM]$/.test(s);

/** A row the user added but left entirely blank is silently ignored on submit. */
export const isBlankVolRow = (r: VolumeRow) =>
  !r.name.trim() && !r.path.trim() && !r.size.trim();

/** A started row is valid only when all three fields individually validate. */
export const isValidVolRow = (r: VolumeRow) =>
  isValidVolName(r.name.trim()) && isValidVolPath(r.path.trim()) && isValidVolSize(r.size.trim());
