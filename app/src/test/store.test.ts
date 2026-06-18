import { renderHook, waitFor, act } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";

const { list, daemonStatus } = vi.hoisted(() => ({
  list: vi.fn(),
  daemonStatus: vi.fn(),
}));
vi.mock("../lib/ipc", () => ({ api: { list, daemonStatus } }));

import { usePolling } from "../lib/store";

const status = { version: "0.3.1", pid: 1, uptime_ms: 1, sandbox_count: 0 };

describe("usePolling phase", () => {
  beforeEach(() => vi.clearAllMocks());

  it("starts in the connecting phase before the first poll settles", () => {
    // A never-resolving poll keeps us in the initial phase.
    list.mockReturnValue(new Promise(() => {}));
    daemonStatus.mockReturnValue(new Promise(() => {}));
    const { result } = renderHook(() => usePolling(0));
    expect(result.current.phase).toBe("connecting");
  });

  it("becomes ready once the first poll succeeds", async () => {
    list.mockResolvedValue([]);
    daemonStatus.mockResolvedValue(status);
    const { result } = renderHook(() => usePolling(0));
    await waitFor(() => expect(result.current.phase).toBe("ready"));
    expect(result.current.daemon).toEqual(status);
  });

  it("becomes unreachable when the first poll fails", async () => {
    list.mockRejectedValue(new Error("daemon unreachable"));
    daemonStatus.mockRejectedValue(new Error("daemon unreachable"));
    const { result } = renderHook(() => usePolling(0));
    await waitFor(() => expect(result.current.phase).toBe("unreachable"));
    expect(result.current.error).toMatch(/unreachable/);
  });

  it("recovers to ready after a transient failure", async () => {
    list.mockRejectedValueOnce(new Error("down")).mockResolvedValue([]);
    daemonStatus.mockRejectedValueOnce(new Error("down")).mockResolvedValue(status);
    const { result } = renderHook(() => usePolling(0));
    await waitFor(() => expect(result.current.phase).toBe("unreachable"));
    await act(() => result.current.refresh());
    await waitFor(() => expect(result.current.phase).toBe("ready"));
  });
});
