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

  it("shellWrite invokes shell_write with name and data", async () => {
    invoke.mockResolvedValue(undefined);
    await api.shellWrite("web", "ls\n");
    expect(invoke).toHaveBeenCalledWith("shell_write", { name: "web", data: "ls\n" });
  });

  it("shellResize invokes shell_resize with dimensions", async () => {
    invoke.mockResolvedValue(undefined);
    await api.shellResize("web", 80, 24);
    expect(invoke).toHaveBeenCalledWith("shell_resize", { name: "web", cols: 80, rows: 24 });
  });

  it("b64ToBytes decodes base64 to bytes", () => {
    // btoa("hi") === "aGk="
    expect(Array.from(b64ToBytes("aGk="))).toEqual([104, 105]);
  });
});
