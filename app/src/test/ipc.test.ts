import { describe, it, expect, vi, beforeEach } from "vitest";

const { invoke, listen } = vi.hoisted(() => ({ invoke: vi.fn(), listen: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/api/event", () => ({ listen }));

import { api, onCreateProgress, b64ToBytes } from "../lib/ipc";

describe("ipc action wrappers", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    invoke.mockResolvedValue(undefined);
    listen.mockResolvedValue(() => {});
  });

  it("start/stop/restart pass the name", async () => {
    await api.start("web");
    await api.stop("web");
    await api.restart("web");
    expect(invoke).toHaveBeenCalledWith("start", { name: "web" });
    expect(invoke).toHaveBeenCalledWith("stop", { name: "web" });
    expect(invoke).toHaveBeenCalledWith("restart", { name: "web" });
  });

  it("remove passes name + force", async () => {
    await api.remove("web", true);
    expect(invoke).toHaveBeenCalledWith("remove", { name: "web", force: true });
  });

  it("create passes opts", async () => {
    const opts = {
      name: "web",
      image: "ubuntu:24.04",
      cpus: 2,
      mem_mb: 4096,
      workspace: "/ws",
      rw_size_gb: 8,
      ports: [],
      volumes: [],
    };
    await api.create(opts);
    expect(invoke).toHaveBeenCalledWith("create", { opts });
  });

  it("onCreateProgress subscribes to the event", async () => {
    await onCreateProgress(() => {});
    expect(listen).toHaveBeenCalledWith("create-progress", expect.any(Function));
  });

  it("readLogs invokes read_logs with the name", async () => {
    invoke.mockResolvedValue("logs!");
    await api.readLogs("web");
    expect(invoke).toHaveBeenCalledWith("read_logs", { name: "web" });
  });

  it("shellOpen invokes shell_open with the name and id", async () => {
    invoke.mockResolvedValue(undefined);
    await api.shellOpen("web", "sh-0");
    expect(invoke).toHaveBeenCalledWith("shell_open", { name: "web", id: "sh-0" });
  });

  it("shellWrite invokes shell_write with id and data", async () => {
    invoke.mockResolvedValue(undefined);
    await api.shellWrite("sh-0", "ls\n");
    expect(invoke).toHaveBeenCalledWith("shell_write", { id: "sh-0", data: "ls\n" });
  });

  it("shellResize invokes shell_resize with id and dimensions", async () => {
    invoke.mockResolvedValue(undefined);
    await api.shellResize("sh-0", 80, 24);
    expect(invoke).toHaveBeenCalledWith("shell_resize", { id: "sh-0", cols: 80, rows: 24 });
  });

  it("shellClose invokes shell_close with the id", async () => {
    invoke.mockResolvedValue(undefined);
    await api.shellClose("sh-0");
    expect(invoke).toHaveBeenCalledWith("shell_close", { id: "sh-0" });
  });

  it("b64ToBytes decodes base64 to bytes", () => {
    // btoa("hi") === "aGk="
    expect(Array.from(b64ToBytes("aGk="))).toEqual([104, 105]);
  });

  it("policyAddEndpoints invokes policy_add_endpoints with entries + enforce", async () => {
    await api.policyAddEndpoints(
      "web",
      [{ kind: "http", host: "pypi.org", port: 443, access: "read" }],
      true,
    );
    expect(invoke).toHaveBeenCalledWith("policy_add_endpoints", {
      name: "web",
      entries: [{ kind: "http", host: "pypi.org", port: 443, access: "read" }],
      enforce: true,
    });
  });

  // ── new bindings added in MVP-B ─────────────────────────────────────────────

  it("inspect invokes inspect with the name", async () => {
    invoke.mockResolvedValue({});
    await api.inspect("web");
    expect(invoke).toHaveBeenCalledWith("inspect", { name: "web" });
  });

  it("portList invokes port_list with the name", async () => {
    invoke.mockResolvedValue([]);
    await api.portList("web");
    expect(invoke).toHaveBeenCalledWith("port_list", { name: "web" });
  });

  it("portPublish invokes port_publish with name, rule, persist", async () => {
    await api.portPublish("web", "0.0.0.0:8080:80", true);
    expect(invoke).toHaveBeenCalledWith("port_publish", {
      name: "web",
      rule: "0.0.0.0:8080:80",
      persist: true,
    });
  });

  it("portUnpublish invokes port_unpublish with name, bind, hostPort", async () => {
    await api.portUnpublish("web", "0.0.0.0", 8080);
    expect(invoke).toHaveBeenCalledWith("port_unpublish", {
      name: "web",
      bind: "0.0.0.0",
      hostPort: 8080,
    });
  });

  it("volumeList invokes volume_list with no args", async () => {
    invoke.mockResolvedValue([]);
    await api.volumeList();
    expect(invoke).toHaveBeenCalledWith("volume_list");
  });

  it("volumeRemove invokes volume_remove with the name", async () => {
    await api.volumeRemove("mydata");
    expect(invoke).toHaveBeenCalledWith("volume_remove", { name: "mydata" });
  });

  it("volumePrune invokes volume_prune with no args", async () => {
    invoke.mockResolvedValue({ removed: [], reclaimed_bytes: 0 });
    await api.volumePrune();
    expect(invoke).toHaveBeenCalledWith("volume_prune");
  });

  it("volumeAttach invokes volume_attach with name and spec", async () => {
    await api.volumeAttach("web", "cache:/data:1g");
    expect(invoke).toHaveBeenCalledWith("volume_attach", {
      name: "web",
      spec: "cache:/data:1g",
    });
  });

  it("volumeDetach invokes volume_detach with name and guestPath", async () => {
    await api.volumeDetach("web", "/data");
    expect(invoke).toHaveBeenCalledWith("volume_detach", {
      name: "web",
      guestPath: "/data",
    });
  });
});
