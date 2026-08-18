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
  /** Whether this sandbox runs in docker mode (#198). */
  docker: boolean;
  cpus: number;
  mem_mb: number;
  /** Host-side VMM confinement summary, or `null` when the sandbox is
   *  stopped / its state predates the field — the UI renders `null` as
   *  "unknown". */
  confinement: string | null;
  /** Whether this sandbox is configured to boot with a VNC desktop. */
  vnc: boolean;
  /** Whether a VNC relay is currently live for this sandbox. */
  vnc_running: boolean;
  /** The URL a human can open to reach the live VNC desktop, when one is
   *  running. */
  vnc_url: string | null;
  /** The sandbox is running with its VNC display configuration ahead of
   *  what it actually booted (either direction) — it must be restarted for
   *  `vnc` to take effect. */
  vnc_restart_required: boolean;
}

/** One process in the guest's mini-top (mirrors `ProcessView`). `state` is
 *  the kernel state char rendered as a JSON-friendly string ("R", "S", …). */
export interface ProcSample {
  pid: number;
  comm: string;
  state: string;
  cpu_permille: number;
  rss_kb: number;
}

/** Filesystem-level fullness of one guest mount (mirrors `MountView`). */
export interface MountUsage {
  path: string;
  total_bytes: number;
  avail_bytes: number;
}

/** Nested Docker Engine liveness (mirrors `DockerEngineView`). */
export interface DockerEngine {
  running: boolean;
  /** When `!running`: a bounded tail of the engine log. */
  detail: string | null;
}

/** Host-observed process resource usage for a running sandbox's VMM
 *  (mirrors `HostResourcesView`). */
export interface HostResources {
  /** CPU share over the sampling interval, in permille of one host CPU.
   *  `null` when a single sample can't yet yield a rate (first read). */
  cpu_permille: number | null;
  rss_kb: number;
  cpus_limit: number;
  mem_limit_mb: number;
}

/** One declared volume's disk footprint (mirrors `VolumeDiskView`). */
export interface VolumeDisk {
  guest_path: string;
  allocated_bytes: number;
  /** Whether this is the auto-provisioned docker-mode volume. */
  docker: boolean;
}

/** Host-computed on-disk footprint for a sandbox (mirrors `HostDiskView`). */
export interface HostDisk {
  rw_img_bytes: number;
  volumes: VolumeDisk[];
  logs_bytes: number;
  /** The rootfs image's on-disk size. Shared by every sandbox created from
   *  the same image — do NOT sum across sandboxes. */
  image_bytes: number;
}

/** Guest-side stats payload (mirrors `GuestStatsView`). Everything here is
 *  guest-reported and already sanitized by the daemon before it reaches the
 *  frontend. */
export interface GuestStats {
  /** Top processes by CPU over the sampling interval, descending. */
  processes: ProcSample[];
  /** Total live processes in the guest. */
  process_count: number;
  /** Load averages × 100. */
  load1_centi: number;
  load5_centi: number;
  load15_centi: number;
  mem_total_kb: number;
  mem_available_kb: number;
  mounts: MountUsage[];
  /** `null` unless the guest booted with `izba.docker=1`. */
  docker: DockerEngine | null;
  /** In-guest workload container state token, or `null`. */
  container: string | null;
}

/** Resource stats for one sandbox (#203, mirrors `SandboxStatsView`). */
export interface SandboxStats {
  name: string;
  running: boolean;
  /** Wall time since the VM process started, when running. */
  uptime_ms: number | null;
  /** Host-observed CPU/RSS + the sandbox's configured limits. `null` when
   *  not running. */
  host: HostResources | null;
  disk: HostDisk;
  /** Sanitized guest-reported mini-top/mounts/docker-engine snapshot.
   *  `null` when the sandbox is stopped or the guest could not be reached. */
  guest: GuestStats | null;
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
  /** Boot with the KasmVNC desktop (--vnc). */
  vnc: boolean;
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
 *  means the web defaults (matching Rust's `AllowEntry::ports()`).
 *
 *  `protocol` is likewise OPTIONAL and likewise `skip_serializing_if =
 *  "Option::is_none"` on the Rust side (`AllowEntry::Scoped.protocol`, the M5
 *  inspectability axis — `http` means izbad terminates and polices this entry
 *  at L7, an explicit `tcp` is the documented TLS-pinning passthrough). The
 *  GUI has NO authoring surface for this field (that stays in `policy.yaml` /
 *  `izba.yml` + `izba diff`/`promote`, which is also where a weakening from
 *  `http` to `tcp` is flagged) — but a value it *read* MUST survive a Save it
 *  did not intend to change: dropping it here silently disables L7
 *  enforcement outside the diff/promote gate (F-1). */
export type AllowEntry =
  | string
  | { host: string; ports?: number[]; access?: Access; protocol?: "http" | "tcp" };

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
