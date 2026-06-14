import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { TopBar } from "../components/TopBar";
import type { DaemonStatusView } from "../lib/types";

const daemon: DaemonStatusView = { version: "0.3.1", pid: 1, uptime_ms: 1, sandbox_count: 0 };

describe("TopBar", () => {
  it("shows the daemon version when running", () => {
    render(<TopBar daemon={daemon} error={null} />);
    expect(screen.getByText(/daemon running/i)).toBeInTheDocument();
    expect(screen.getByText(/v0\.3\.1/)).toBeInTheDocument();
  });

  it("shows an unreachable state when there is an error", () => {
    render(<TopBar daemon={null} error="daemon unreachable" />);
    expect(screen.getByText(/daemon unreachable/i)).toBeInTheDocument();
    expect(screen.queryByText(/daemon running/i)).not.toBeInTheDocument();
  });
});
