import { renderHook, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { usePolling } from "./store";

vi.mock("./ipc", () => ({
  api: {
    list: vi.fn().mockResolvedValue([{ name: "web", image: "ubuntu:24.04", state: { kind: "running" } }]),
    daemonStatus: vi.fn().mockResolvedValue({ version: "0.3.1", pid: 1, uptime_ms: 1, sandbox_count: 1 }),
  },
}));

describe("usePolling", () => {
  beforeEach(() => vi.clearAllMocks());

  it("loads sandboxes and daemon status on mount", async () => {
    const { result } = renderHook(() => usePolling(0)); // 0 = no repeat, one immediate fetch
    await waitFor(() => expect(result.current.sandboxes.length).toBe(1));
    expect(result.current.sandboxes[0].name).toBe("web");
    expect(result.current.daemon?.version).toBe("0.3.1");
    expect(result.current.error).toBeNull();
  });

  it("surfaces errors from list", async () => {
    const { api } = await import("./ipc");
    (api.list as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error("daemon unreachable"));
    const { result } = renderHook(() => usePolling(0));
    await waitFor(() => expect(result.current.error).toContain("daemon unreachable"));
  });
});
