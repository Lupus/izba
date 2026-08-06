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

export interface PortRule {
  bind: string;
  host_port: number;
  guest_port: number;
}

export interface VolumeSpec {
  name: string | null;
  guest_path: string;
  size_bytes: number;
  eph_id?: number | null;
}

export interface VolumeInfo {
  name: string;
  size_bytes: number;
  actual_bytes: number;
  referenced_by: string[];
}

export interface SandboxDetail {
  name: string;
  image: string;
  status: string;
  /** Host workspace directory (human-rendered; no Windows `\\?\` prefix). */
  workspace: string;
  ports: PortRule[];
  volumes: VolumeSpec[];
  /** In-guest workload container state token (`running`, `stopped`, …), or
   *  `null` when the sandbox is stopped, the guest was unreachable, or the
   *  daemon predates container-state reporting. `null` and `"unknown"` both
   *  render as "unknown" — never as a healthy status. */
  container: string | null;
}

export interface CreateOpts {
  name: string;
  image: string;
  cpus: number;
  mem_mb: number;
  workspace: string;
  rw_size_gb: number;
  ports: string[];
  volumes: string[];
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

/** Drift between the repo's `izba.yml` proposal and the host-managed truth. */
export type DriftState = "in_sync" | "repo_ahead" | "managed_ahead" | "diverged";

/** One field-level delta in a manifest diff/promote result. */
export interface DeltaView {
  field: string;
  from: string;
  to: string;
  class: "live" | "restart" | "image";
  weakens_egress: boolean;
}

export interface DiffView {
  state: DriftState;
  deltas: DeltaView[];
}

/** Mirrors izba_core's `PromoteView` (`{state, applied, needs_restart, restarted, stopped, warnings}`). */
export interface PromoteView {
  state: DriftState;
  applied: DeltaView[];
  needs_restart: boolean;
  restarted: boolean;
  stopped: boolean;
  warnings: string[];
}

/** The configured usbip upstream (mirrors `UsbUpstreamView`). */
export interface UsbUpstream {
  host: string;
  port: number;
  resolved: string | null;
  /** Stable kebab-case trust token, e.g. "own-host-loopback". */
  trust: string;
  /** The note for that trust class; null for the recommended (loopback) one. */
  warning: string | null;
}

/** One row of the upstream device inventory (mirrors `UsbDeviceView`). */
export interface UsbDevice {
  busid: string;
  /** Canonical `vid:pid`. */
  device: string;
  description: string;
  /** Whether the upstream is currently exporting it. */
  shared: boolean;
  granted_to: string[];
  /** The sandbox holding it right now, if any. */
  attached_to: string | null;
  /** For an unshared device: the exact command a human must run elevated.
   *  izba never runs it. */
  bind_command: string | null;
}

/** One standing grant, with live attachment state folded in. */
export interface UsbGrant {
  device: string;
  busid_pin: string | null;
  description: string;
  granted_at_unix_ms: number;
  attached: boolean;
}

export interface UsbStatus {
  grants: UsbGrant[];
  /** The sandbox holds a grant its running kernel cannot honour: the USB kernel
   *  is chosen at boot, so this one needs a restart before it can attach. */
  restart_required: boolean;
}
