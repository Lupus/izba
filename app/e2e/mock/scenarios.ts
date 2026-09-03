import type {
  SandboxView,
  SandboxDetail,
  DaemonStatusView,
  VersionView,
  BuildInfo,
  CreateOpts,
  EndpointSummary,
  PolicyView,
  SandboxStats,
  PortRule,
  VolumeInfo,
  UsbUpstream,
  UsbDevice,
  UsbStatus,
} from "../../src/lib/types";

export interface Scenario {
  sandboxes: SandboxView[];
  daemonStatus?: DaemonStatusView;
  version?: VersionView;
  logs?: string;
  netlog?: EndpointSummary[];
  policy?: Record<string, PolicyView>;
  /** `inspect` responses keyed by sandbox name (OverviewTab, DisplayTab, …
   *  all fetch it). Mutated in place by the mock's `vnc_set` arm. */
  details?: Record<string, SandboxDetail>;
  /** `stats` responses keyed by sandbox name; a sandbox with no entry gets
   *  a canned stopped snapshot. */
  stats?: Record<string, SandboxStats>;
  /** `port_list` responses keyed by sandbox name (default `[]`). */
  ports?: Record<string, PortRule[]>;
  /** `volume_list` response (default `[]`). */
  volumes?: VolumeInfo[];
  /** `usb_upstream_show` response; `null`/absent = USB feature off. */
  usbUpstream?: UsbUpstream | null;
  /** `usb_list_devices` response (default `[]`). */
  usbDevices?: UsbDevice[];
  /** `usb_status` responses keyed by sandbox name (default: no grants). */
  usbStatus?: Record<string, UsbStatus>;
  failList?: boolean;
  failStatus?: boolean;
  /** Makes `stats` reject instead of answering — pins OverviewTab's
   *  "stats unavailable" degraded-state banner (unreachable before this
   *  flag existed, since `stats` had no scenario knob at all). */
  failStats?: boolean;
  failAction?: boolean;
  daemonAbsent?: boolean;
  errorMessage?: string;
  createName?: string;
  createError?: string;
  createDeferred?: boolean;
}

function buildInfo(over: Partial<BuildInfo> = {}): BuildInfo {
  return {
    pkg_version: "0.3.1",
    git_describe: "v0.3.1",
    git_sha: "abc1234",
    commit_date: "2026-06-20",
    build_timestamp: "2026-06-20T00:00:00Z",
    rustc: "rustc 1.80.0",
    target: "x86_64-unknown-linux-gnu",
    profile: "release",
    ...over,
  };
}

/** Mirrors the Rust daemon's `SandboxDetail` shape; every field the GUI reads
 *  (OverviewTab, PortsTab, VolumesTab, DisplayTab, WorkspacePath) gets an
 *  inert default so a spec need only override what it cares about. */
function sandboxDetail(over: Partial<SandboxDetail> = {}): SandboxDetail {
  return {
    name: "web",
    image: "ubuntu:24.04",
    status: "running",
    workspace: "/ws",
    ports: [],
    volumes: [],
    container: null,
    docker: false,
    cpus: 2,
    mem_mb: 2048,
    confinement: null,
    vnc: false,
    vnc_running: false,
    vnc_url: null,
    vnc_restart_required: false,
    ...over,
  };
}

/** Mirrors the Rust FakeDaemon::default seed. */
export function defaultScenario(): Scenario {
  return {
    sandboxes: [
      { name: "web", image: "ubuntu:24.04", state: { kind: "running" } },
      { name: "db", image: "postgres:16", state: { kind: "stopped" } },
    ],
    daemonStatus: { version: "0.3.1", pid: 4242, uptime_ms: 1000, sandbox_count: 2 },
    version: {
      app: buildInfo(),
      core: buildInfo(),
      daemon: buildInfo(),
      proto: 1,
      mismatch: false,
    },
    logs: "boot ok\nlogin:\n",
    netlog: [],
    policy: {},
    details: {
      web: sandboxDetail({ name: "web", image: "ubuntu:24.04", status: "running", workspace: "/ws/web" }),
      db: sandboxDetail({ name: "db", image: "postgres:16", status: "stopped", workspace: "/ws/db" }),
    },
  };
}

/** A running sandbox with a live, credentialed desktop — the Display tab's
 *  "url" presentation (`vncPresentation` in src/lib/vnc.ts). `vnc_url`
 *  carries the desktop password in its userinfo exactly like the real
 *  backend, so display.spec.ts's credential-leak assertion is genuine: a
 *  regression that rendered this URL (instead of the proxy URL) would trip
 *  it. */
export function vncEnabledScenario(): Scenario {
  const base = defaultScenario();
  return {
    ...base,
    details: {
      ...base.details,
      web: sandboxDetail({
        name: "web",
        image: "ubuntu:24.04",
        status: "running",
        workspace: "/ws/web",
        vnc: true,
        vnc_running: true,
        vnc_url: "http://izba:pw@127.0.0.1:4444/",
      }),
    },
  };
}

export type { CreateOpts };
