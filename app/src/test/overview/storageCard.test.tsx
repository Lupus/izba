import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { runningStats, stoppedStats } from "./fixtures";

import { StorageCard } from "../../components/overview/StorageCard";

describe("StorageCard", () => {
  it("headlines the on-host footprint with the shared image excluded", () => {
    // rw 1.2 GiB + docker 2.1 GiB + volume 400 MiB + logs 12 MiB = 3.7 GiB.
    // The 890 MiB image is shared between sandboxes and must NOT be summed in.
    render(<StorageCard stats={runningStats()} />);
    expect(screen.getByText(/3\.7 GiB on host/)).toBeInTheDocument();
    expect(screen.queryByText(/4\.6 GiB on host/)).not.toBeInTheDocument();
  });

  it("lists every non-zero segment in the legend", () => {
    render(<StorageCard stats={runningStats()} />);
    expect(screen.getByText("2.1 GiB")).toBeInTheDocument(); // docker
    expect(screen.getByText("1.2 GiB")).toBeInTheDocument(); // writable layer
    expect(screen.getByText("400.0 MiB")).toBeInTheDocument(); // volumes
    expect(screen.getByText("12.0 MiB")).toBeInTheDocument(); // logs
  });

  it("adds guest-reported docker fullness when the mount is known", () => {
    render(<StorageCard stats={runningStats()} />);
    expect(screen.getByText("(21% of 10.0 GiB)")).toBeInTheDocument();
  });

  it("omits docker fullness when the guest does not report the mount", () => {
    render(<StorageCard stats={runningStats({ guest: null })} />);
    expect(screen.getByText("2.1 GiB")).toBeInTheDocument();
    expect(screen.queryByText(/% of/)).not.toBeInTheDocument();
  });

  it("shows the shared image as a trailing note, not part of the total", () => {
    render(<StorageCard stats={runningStats()} />);
    expect(screen.getByText("+ image 890.0 MiB (shared)")).toBeInTheDocument();
  });

  it("has no docker segment for a non-docker sandbox", () => {
    const s = runningStats();
    render(
      <StorageCard
        stats={runningStats({
          disk: { ...s.disk, volumes: s.disk.volumes.filter((v) => !v.docker) },
        })}
      />,
    );
    expect(screen.queryByText("docker")).not.toBeInTheDocument();
    expect(screen.getByText(/1\.6 GiB on host/)).toBeInTheDocument();
  });

  it("stays fully live for a stopped sandbox", () => {
    render(<StorageCard stats={stoppedStats()} />);
    expect(screen.getByText(/3\.7 GiB on host/)).toBeInTheDocument();
    expect(screen.queryByText(/not running/)).not.toBeInTheDocument();
  });
});
