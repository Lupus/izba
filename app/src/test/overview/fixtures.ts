import type { SandboxDetail, SandboxStats } from "../../lib/types";

/** Shared fixtures for the Overview card tests. The numbers mirror the
 *  approved spec mock-up (and FakeDaemon's shape from Task 7) so the card
 *  tests can assert the exact strings a user sees:
 *
 *    CPU  34% of 4 vCPU      (1360 permille / 4 000)
 *    MEM  2.5 GiB / 4.0 GiB  (host rss vs the configured limit)
 *    guest 1.9 GiB used of 4.0 GiB · load 0.42 · 61 processes
 *    storage 3.7 GiB on host (rw 1.2 + docker 2.1 + vol 400 MiB + logs 12 MiB)
 */
export function runningStats(overrides: Partial<SandboxStats> = {}): SandboxStats {
  return {
    name: "web",
    running: true,
    uptime_ms: 8_040_000, // 2h 14m
    host: {
      cpu_permille: 1_360,
      rss_kb: 2_621_440, // 2.5 GiB
      cpus_limit: 4,
      mem_limit_mb: 4096,
    },
    disk: {
      rw_img_bytes: 1_288_490_189, // 1.2 GiB
      volumes: [
        { guest_path: "/var/lib/docker", allocated_bytes: 2_254_857_830, docker: true }, // 2.1 GiB
        { guest_path: "/data", allocated_bytes: 419_430_400, docker: false }, // 400.0 MiB
      ],
      logs_bytes: 12_582_912, // 12.0 MiB
      image_bytes: 933_232_640, // 890.0 MiB — shared, excluded from the headline
    },
    guest: {
      processes: [
        { pid: 42, comm: "node", state: "R", cpu_permille: 210, rss_kb: 65_536 },
        { pid: 77, comm: "dockerd", state: "S", cpu_permille: 12, rss_kb: 32_768 },
        { pid: 1, comm: "init", state: "S", cpu_permille: 5, rss_kb: 4_096 },
      ],
      process_count: 61,
      load1_centi: 42,
      load5_centi: 30,
      load15_centi: 19,
      mem_total_kb: 4_194_304, // 4.0 GiB
      mem_available_kb: 2_202_010, // → 1.9 GiB used
      mounts: [
        { path: "/var/lib/docker", total_bytes: 10 * 1024 ** 3, avail_bytes: 8 * 1024 ** 3 },
      ],
      docker: { running: true, detail: null },
      container: "running",
    },
    ...overrides,
  };
}

/** A stopped sandbox: host + guest tiers gone, the disk tier still live. */
export function stoppedStats(overrides: Partial<SandboxStats> = {}): SandboxStats {
  return {
    ...runningStats(),
    running: false,
    uptime_ms: null,
    host: null,
    guest: null,
    ...overrides,
  };
}

export function detailFixture(overrides: Partial<SandboxDetail> = {}): SandboxDetail {
  return {
    name: "web",
    image: "ghcr.io/acme/node:20",
    status: "running",
    workspace: "/home/u/git/web",
    ports: [],
    volumes: [],
    container: "running",
    docker: true,
    cpus: 4,
    mem_mb: 4096,
    confinement: "confined",
    ...overrides,
  };
}
