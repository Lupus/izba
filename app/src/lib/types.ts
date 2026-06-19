export type SbxState =
  | { kind: "running" }
  | { kind: "degraded"; reason: string }
  | { kind: "stopped" };

export interface SandboxView {
  name: string;
  image: string;
  state: SbxState;
}

export interface DaemonStatusView {
  version: string;
  pid: number;
  uptime_ms: number;
  sandbox_count: number;
}

/** Build metadata for one component (mirrors izba_core::build_info::BuildInfoOwned). */
export interface BuildInfo {
  pkg_version: string;
  git_describe: string;
  git_sha: string;
  commit_date: string;
  build_timestamp: string;
  rustc: string;
  target: string;
  profile: string;
}

/** App / core / daemon builds + a mismatch flag, for the About panel. */
export interface VersionView {
  app: BuildInfo;
  core: BuildInfo;
  daemon: BuildInfo | null;
  proto: number;
  mismatch: boolean;
}

export interface CreateOpts {
  name: string;
  image: string;
  cpus: number;
  mem_mb: number;
  workspace: string;
  rw_size_gb: number;
  ports: string[];
}

/** Payload of the `shell-output` event (raw PTY bytes, base64-encoded). */
export interface ShellOutputPayload {
  id: string;
  data: string;
}

/** Payload of the `shell-exit` event. */
export interface ShellExitPayload {
  id: string;
}

export type Tier = "l7" | "l3";
export type Verdict = "allow" | "deny";

export interface EndpointSummary {
  host: string | null;
  dest_ip: string;
  port: number;
  tier: Tier;
  verdict: Verdict;
  allow_count: number;
  deny_count: number;
  first_seen_ms: number;
  last_seen_ms: number;
  last_method: string | null;
  last_path: string | null;
}

/** Untagged on the Rust side: a bare host is a string, a scoped host an object.
 *  `ports` is OPTIONAL: the backend serializes `ports: Option<Vec<u16>>` with
 *  `skip_serializing_if = "Option::is_none"`, so a scoped entry whose ports
 *  equal the web defaults comes back with NO `ports` field. A missing `ports`
 *  means the web defaults (matching Rust's `AllowEntry::ports()`). */
export type AllowEntry = string | { host: string; ports?: number[]; access?: Access };

export type Access = "read" | "read-write";

/** A git rule from the policy: either a repo URL or a hostname, with optional access level. */
export type GitRule = ({ repo: string } | { host: string }) & { access?: Access };

export type SeedEntry =
  | { kind: "http"; host: string; port: number; access: Access }
  | { kind: "git"; target: string; access: Access };

export interface PolicyView {
  enforcing: boolean;
  allow: AllowEntry[];
  git: GitRule[];
}
