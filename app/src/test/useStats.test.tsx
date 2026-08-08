import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { SandboxStats } from "../lib/types";

// ── hoisted mocks ────────────────────────────────────────────────────────────

const { stats } = vi.hoisted(() => ({ stats: vi.fn() }));

vi.mock("../lib/ipc", () => ({
  api: { stats },
}));

import { useStats } from "../lib/useStats";

// ── helpers ──────────────────────────────────────────────────────────────────

function fixture(name = "web"): SandboxStats {
  return {
    name,
    running: true,
    uptime_ms: 1_000,
    host: null,
    disk: { rw_img_bytes: 0, volumes: [], logs_bytes: 0, image_bytes: 0 },
    guest: null,
  };
}

beforeEach(() => {
  vi.useFakeTimers();
  stats.mockReset();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("useStats", () => {
  it("resolves the first tick immediately", async () => {
    stats.mockResolvedValue(fixture());
    const { result } = renderHook(() => useStats("web", 1000));

    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    expect(result.current.stats?.name).toBe("web");
    expect(result.current.error).toBeNull();
    expect(stats).toHaveBeenCalledTimes(1);
    expect(stats).toHaveBeenCalledWith("web");
  });

  it("keeps the last good stats and surfaces an error when a later tick fails", async () => {
    stats.mockResolvedValueOnce(fixture());
    stats.mockRejectedValueOnce(new Error("daemon restarting"));
    const { result } = renderHook(() => useStats("web", 1000));

    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(result.current.stats?.name).toBe("web");

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });

    // Last good snapshot survives the failed tick, alongside the error.
    expect(result.current.stats?.name).toBe("web");
    expect(result.current.error).toBe("daemon restarting");
  });

  it("skips overlapping ticks while a call is in flight", async () => {
    let resolveFirst!: (s: SandboxStats) => void;
    stats.mockImplementationOnce(
      () => new Promise<SandboxStats>((r) => (resolveFirst = r)),
    );
    renderHook(() => useStats("web", 1000));

    // First tick fires and hangs.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(stats).toHaveBeenCalledTimes(1);

    // Several intervals elapse while the first call is still pending: the
    // in-flight guard must skip every one of them.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000);
    });
    expect(stats).toHaveBeenCalledTimes(1);

    // Once the hung call settles, the next interval issues a fresh request.
    resolveFirst(fixture());
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });
    expect(stats).toHaveBeenCalledTimes(2);
  });

  it("clears the interval on unmount so no further calls happen", async () => {
    stats.mockResolvedValue(fixture());
    const { unmount } = renderHook(() => useStats("web", 1000));

    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(stats).toHaveBeenCalledTimes(1);

    unmount();

    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_000);
    });
    expect(stats).toHaveBeenCalledTimes(1);
  });
});
