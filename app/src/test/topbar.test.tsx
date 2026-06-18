import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { TopBar } from "../components/TopBar";
import type { DaemonStatusView } from "../lib/types";

const daemon: DaemonStatusView = { version: "0.3.1", pid: 1, uptime_ms: 1, sandbox_count: 0 };

describe("TopBar", () => {
  it("shows a connecting state before the first poll settles", () => {
    render(<TopBar phase="connecting" daemon={null} onAbout={() => {}} />);
    expect(screen.getByText(/connecting/i)).toBeInTheDocument();
    // Must NOT claim the daemon is running until a status actually arrives.
    expect(screen.queryByText(/daemon running/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/daemon unreachable/i)).not.toBeInTheDocument();
  });

  it("shows the daemon version when ready", () => {
    render(<TopBar phase="ready" daemon={daemon} onAbout={() => {}} />);
    expect(screen.getByText(/daemon running/i)).toBeInTheDocument();
    expect(screen.getByText(/v0\.3\.1/)).toBeInTheDocument();
  });

  it("shows an unreachable state when the daemon cannot be reached", () => {
    render(<TopBar phase="unreachable" daemon={null} onAbout={() => {}} />);
    expect(screen.getByText(/daemon unreachable/i)).toBeInTheDocument();
    expect(screen.queryByText(/daemon running/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/connecting/i)).not.toBeInTheDocument();
    expect(screen.getByText(/about/i)).toBeInTheDocument();
  });
});
