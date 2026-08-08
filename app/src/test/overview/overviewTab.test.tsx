import { act, render, screen, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import type { SandboxView } from "../../lib/types";
import { detailFixture, runningStats } from "./fixtures";

const { stats, inspect, policyShow } = vi.hoisted(() => ({
  stats: vi.fn(),
  inspect: vi.fn(),
  policyShow: vi.fn(),
}));

vi.mock("../../lib/ipc", () => ({ api: { stats, inspect, policyShow } }));

import { OverviewTab } from "../../components/overview/OverviewTab";

const sandbox: SandboxView = {
  name: "web",
  image: "ghcr.io/acme/node:20",
  state: { kind: "running" },
};

beforeEach(() => {
  vi.clearAllMocks();
  policyShow.mockResolvedValue({ enforcing: false, allow: [] });
});

describe("OverviewTab", () => {
  it("renders all four cards from a single stats poll", async () => {
    stats.mockResolvedValue(runningStats());
    inspect.mockResolvedValue(detailFixture());
    render(<OverviewTab sandbox={sandbox} />);

    expect(await screen.findByText("Sandbox")).toBeInTheDocument();
    expect(screen.getByText("Resources")).toBeInTheDocument();
    expect(screen.getByText(/^Storage/)).toBeInTheDocument();
    expect(screen.getByText(/^Processes/)).toBeInTheDocument();
    // One poller for the whole tab, one non-polling inspect.
    expect(stats).toHaveBeenCalledTimes(1);
    expect(stats).toHaveBeenCalledWith("web");
    expect(inspect).toHaveBeenCalledTimes(1);
  });

  it("renders placeholder card bodies instead of crashing when stats fail", async () => {
    stats.mockRejectedValue(new Error("daemon restarting"));
    inspect.mockRejectedValue(new Error("daemon restarting"));
    render(<OverviewTab sandbox={sandbox} />);

    await waitFor(() => expect(stats).toHaveBeenCalled());
    expect(screen.getByText("Sandbox")).toBeInTheDocument();
    expect(screen.getByText("Resources")).toBeInTheDocument();
    expect(screen.getAllByText("…").length).toBeGreaterThan(0);
  });
});

describe("OverviewTab — stale data", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("warns the snapshot may be stale and stops claiming live state once polling fails", async () => {
    stats.mockResolvedValueOnce(runningStats());
    stats.mockRejectedValue(new Error("daemon restarting"));
    inspect.mockResolvedValue(detailFixture());
    render(<OverviewTab sandbox={sandbox} />);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(screen.getByText("running · 2h 14m")).toBeInTheDocument();
    expect(screen.queryByText(/may be stale/i)).not.toBeInTheDocument();

    // Next poll fails: the last good snapshot survives (useStats keeps it), so
    // the tab must say so instead of silently presenting it as current.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3_000);
    });

    expect(screen.getByText(/stats unavailable — last update may be stale/i)).toBeInTheDocument();
    expect(screen.queryByText("running · 2h 14m")).not.toBeInTheDocument();
    expect(screen.getByText("unknown")).toBeInTheDocument(); // container, not "running"
  });
});
