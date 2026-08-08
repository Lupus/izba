import { render, screen } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { containerLabel } from "../../lib/container";
import { detailFixture, runningStats, stoppedStats } from "./fixtures";

// The firewall badge does its own (best-effort) policy fetch; the card test
// only cares that the badge now lives inside the card.
vi.mock("../../components/FirewallStatus", () => ({
  FirewallStatus: ({ name }: { name: string }) => <div>firewall-for-{name}</div>,
}));

import { SandboxCard } from "../../components/overview/SandboxCard";

// Ported from the retired ContainerStatus test: the label set is the honest
// story the card tells about the in-guest workload.
describe("containerLabel", () => {
  it("mirrors the CLI label set", () => {
    expect(containerLabel("running")).toBe("running");
    expect(containerLabel("stopped")).toBe("stopped (workload exited)");
    expect(containerLabel("created")).toBe("created (not started)");
    expect(containerLabel("creating")).toBe("creating");
    expect(containerLabel("paused")).toBe("paused");
  });

  it("never implies healthy for null, unknown, or unrecognized tokens", () => {
    expect(containerLabel(null)).toBe("unknown");
    expect(containerLabel("unknown")).toBe("unknown");
    expect(containerLabel("gibberish")).toBe("unknown");
  });
});

describe("SandboxCard", () => {
  it("shows the state with its uptime", () => {
    render(
      <SandboxCard
        name="web"
        state={{ kind: "running" }}
        detail={detailFixture()}
        stats={runningStats()}
      />,
    );
    expect(screen.getByText("running · 2h 14m")).toBeInTheDocument();
  });

  it("shows the guest-reported container state", () => {
    render(
      <SandboxCard
        name="web"
        state={{ kind: "running" }}
        detail={detailFixture()}
        stats={runningStats({ guest: { ...runningStats().guest!, container: "stopped" } })}
      />,
    );
    expect(screen.getByText("stopped (workload exited)")).toBeInTheDocument();
  });

  it("shows the confinement mode and the workspace path", () => {
    render(
      <SandboxCard
        name="web"
        state={{ kind: "running" }}
        detail={detailFixture()}
        stats={runningStats()}
      />,
    );
    expect(screen.getByText("confined")).toBeInTheDocument();
    expect(screen.getByText("/home/u/git/web")).toBeInTheDocument();
  });

  it("renders the firewall badge inside the card", () => {
    render(
      <SandboxCard
        name="web"
        state={{ kind: "running" }}
        detail={detailFixture()}
        stats={runningStats()}
      />,
    );
    expect(screen.getByText("firewall-for-web")).toBeInTheDocument();
  });

  it("reports a live nested docker engine", () => {
    render(
      <SandboxCard
        name="web"
        state={{ kind: "running" }}
        detail={detailFixture()}
        stats={runningStats()}
      />,
    );
    expect(screen.getByText("engine running")).toBeInTheDocument();
  });

  it("reports a dead docker engine with its log detail", () => {
    const s = runningStats();
    render(
      <SandboxCard
        name="web"
        state={{ kind: "running" }}
        detail={detailFixture()}
        stats={runningStats({
          guest: { ...s.guest!, docker: { running: false, detail: "exec format error" } },
        })}
      />,
    );
    expect(screen.getByText("engine not running — see logs")).toBeInTheDocument();
    expect(screen.getByText("exec format error")).toBeInTheDocument();
  });

  it("says the engine is unknown when the guest does not answer", () => {
    render(
      <SandboxCard
        name="web"
        state={{ kind: "running" }}
        detail={detailFixture()}
        stats={runningStats({ guest: null })}
      />,
    );
    expect(screen.getByText("engine unknown")).toBeInTheDocument();
    // …and the container line degrades to "unknown", never a healthy claim.
    expect(screen.getByText("unknown")).toBeInTheDocument();
  });

  it("has no docker row for a non-docker sandbox", () => {
    render(
      <SandboxCard
        name="web"
        state={{ kind: "running" }}
        detail={detailFixture({ docker: false })}
        stats={runningStats()}
      />,
    );
    expect(screen.queryByText(/engine/i)).not.toBeInTheDocument();
    expect(screen.queryByText("docker")).not.toBeInTheDocument();
  });

  it("drops uptime and the container line for a stopped sandbox", () => {
    render(
      <SandboxCard
        name="db"
        state={{ kind: "stopped" }}
        detail={detailFixture({ name: "db", container: null })}
        stats={stoppedStats({ name: "db" })}
      />,
    );
    expect(screen.getByText("stopped")).toBeInTheDocument();
    expect(screen.queryByText(/2h 14m/)).not.toBeInTheDocument();
    expect(screen.queryByText("container")).not.toBeInTheDocument();
  });
});
