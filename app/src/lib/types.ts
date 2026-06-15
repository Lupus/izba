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

/** Untagged on the Rust side: a bare host is a string, a scoped host an object. */
export type AllowEntry = string | { host: string; ports: number[] };

export interface PolicyView {
  enforcing: boolean;
  allow: AllowEntry[];
}
