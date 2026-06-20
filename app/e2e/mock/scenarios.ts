import type {
  SandboxView,
  DaemonStatusView,
  VersionView,
  BuildInfo,
  CreateOpts,
  EndpointSummary,
  PolicyView,
} from "../../src/lib/types";

export interface Scenario {
  sandboxes: SandboxView[];
  daemonStatus?: DaemonStatusView;
  version?: VersionView;
  logs?: string;
  netlog?: EndpointSummary[];
  policy?: Record<string, PolicyView>;
  failList?: boolean;
  failStatus?: boolean;
  failAction?: boolean;
  daemonAbsent?: boolean;
  errorMessage?: string;
  createName?: string;
  createError?: string;
  createDeferred?: boolean;
  policyEnableCount?: number;
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
  };
}

export type { CreateOpts };
