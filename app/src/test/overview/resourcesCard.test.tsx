import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { runningStats, stoppedStats } from "./fixtures";

import { ResourcesCard } from "../../components/overview/ResourcesCard";

describe("ResourcesCard", () => {
  it("shows the host-observed CPU share against the vCPU limit", () => {
    render(<ResourcesCard stats={runningStats()} />);
    expect(screen.getByText("34%")).toBeInTheDocument();
    expect(screen.getByText("4 vCPU")).toBeInTheDocument();
    expect(screen.getByRole("meter", { name: /cpu/i })).toBeInTheDocument();
  });

  it("shows host memory against the configured limit", () => {
    render(<ResourcesCard stats={runningStats()} />);
    expect(screen.getByText("2.5 GiB / 4.0 GiB")).toBeInTheDocument();
    expect(screen.getByRole("meter", { name: /mem/i })).toBeInTheDocument();
  });

  it("keeps the guest-reported figures as secondary text", () => {
    render(<ResourcesCard stats={runningStats()} />);
    expect(screen.getByText("guest: 1.9 GiB used of 4.0 GiB")).toBeInTheDocument();
    expect(screen.getByText("load 0.42 · 61 processes")).toBeInTheDocument();
  });

  it("renders a quiet placeholder and no bars for a stopped sandbox", () => {
    render(<ResourcesCard stats={stoppedStats()} />);
    expect(screen.getByText("not running")).toBeInTheDocument();
    expect(screen.queryByRole("meter")).not.toBeInTheDocument();
  });

  it("falls back to guest-derived memory with no bars when the host tier is absent", () => {
    // Non-Linux host: no /proc, so no trusted host tier — and therefore no bars.
    render(<ResourcesCard stats={runningStats({ host: null })} />);
    expect(screen.queryByRole("meter")).not.toBeInTheDocument();
    expect(screen.queryByText("34%")).not.toBeInTheDocument();
    expect(screen.getByText("guest: 1.9 GiB used of 4.0 GiB")).toBeInTheDocument();
  });

  it("keeps the host bars live when the guest is unreachable", () => {
    // Spec §7: the host tier is measured on the host — an unresponsive guest
    // must not blank the bars, only the guest-reported secondary lines.
    render(<ResourcesCard stats={runningStats({ guest: null })} />);
    expect(screen.getByRole("meter", { name: /cpu/i })).toBeInTheDocument();
    expect(screen.getByRole("meter", { name: /mem/i })).toBeInTheDocument();
    expect(screen.getByText("34%")).toBeInTheDocument();
    expect(screen.queryByText(/^guest:/)).not.toBeInTheDocument();
    expect(screen.queryByText(/^load /)).not.toBeInTheDocument();
  });

  it("says plainly that no tier reported when both are absent", () => {
    render(<ResourcesCard stats={runningStats({ host: null, guest: null })} />);
    expect(screen.getByText("no resource data")).toBeInTheDocument();
    expect(screen.queryByRole("meter")).not.toBeInTheDocument();
  });

  it("omits the CPU bar until the sampler has a rate", () => {
    const s = runningStats();
    render(<ResourcesCard stats={runningStats({ host: { ...s.host!, cpu_permille: null } })} />);
    expect(screen.queryByRole("meter", { name: /cpu/i })).not.toBeInTheDocument();
    expect(screen.getByRole("meter", { name: /mem/i })).toBeInTheDocument();
  });
});
