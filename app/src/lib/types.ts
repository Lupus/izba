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
