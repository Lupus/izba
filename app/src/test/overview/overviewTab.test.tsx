import { render, screen, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
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
