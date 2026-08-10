import { describe, it, expect } from "vitest";
import type { SandboxDetail } from "../lib/types";
import { vncPresentation } from "../lib/vnc";

// Full SandboxDetail literal with overridable vnc-relevant fields, mirroring
// the CLI's own `detail()` test helper in `crates/izba-cli/src/commands/vnc.rs`.
function detail(overrides: Partial<SandboxDetail> = {}): SandboxDetail {
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
    mem_mb: 4096,
    confinement: null,
    vnc: false,
    vnc_running: false,
    vnc_url: null,
    vnc_restart_required: false,
    ...overrides,
  };
}

describe("vncPresentation", () => {
  it("not enabled, no url -> not-enabled", () => {
    const d = detail({ vnc: false, status: "running", vnc_running: false, vnc_url: null });
    expect(vncPresentation(d)).toEqual({ kind: "not-enabled" });
  });

  it("enabled, stopped -> not-running", () => {
    const d = detail({ vnc: true, status: "stopped", vnc_running: false, vnc_url: null });
    expect(vncPresentation(d)).toEqual({ kind: "not-running" });
  });

  it("enabled, running, no url -> restart-required", () => {
    const d = detail({ vnc: true, status: "running", vnc_running: false, vnc_url: null });
    expect(vncPresentation(d)).toEqual({ kind: "restart-required" });
  });

  it("enabled, running, url, vnc_running -> url with no warnings", () => {
    const d = detail({
      vnc: true,
      status: "running",
      vnc_running: true,
      vnc_url: "http://izba:s3cr3t@127.0.0.1:4444/",
    });
    expect(vncPresentation(d)).toEqual({
      kind: "url",
      url: "http://izba:s3cr3t@127.0.0.1:4444/",
      warnings: [],
    });
  });

  it("disabled but url present (live off) -> url with exactly the disabled warning", () => {
    const d = detail({
      vnc: false,
      status: "running",
      vnc_running: true,
      vnc_url: "http://izba:s3cr3t@127.0.0.1:4444/",
    });
    expect(vncPresentation(d)).toEqual({
      kind: "url",
      url: "http://izba:s3cr3t@127.0.0.1:4444/",
      warnings: ["VNC is disabled in config — this desktop stops at the next restart."],
    });
  });

  it("enabled, url present, vnc_running false -> url with exactly the dead-desktop warning", () => {
    const d = detail({
      vnc: true,
      status: "running",
      vnc_running: false,
      vnc_url: "http://izba:s3cr3t@127.0.0.1:4444/",
    });
    expect(vncPresentation(d)).toEqual({
      kind: "url",
      url: "http://izba:s3cr3t@127.0.0.1:4444/",
      warnings: ["The desktop is not answering. Guest log: izba exec web -- cat /var/log/izba-vnc.log"],
    });
  });
});
