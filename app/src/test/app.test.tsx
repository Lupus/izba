import { render, screen, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";

const { list, daemonStatus } = vi.hoisted(() => ({ list: vi.fn(), daemonStatus: vi.fn() }));
vi.mock("../lib/ipc", () => ({
  api: { list, daemonStatus },
  onShellOutput: vi.fn(() => Promise.resolve(() => {})),
  onShellExit: vi.fn(() => Promise.resolve(() => {})),
  onCreateProgress: vi.fn(() => Promise.resolve(() => {})),
}));

// The component tree pulls in xterm via ShellPanel; stub it for jsdom.
vi.mock("@xterm/xterm", () => ({
  Terminal: vi.fn(() => ({
    open: vi.fn(),
    write: vi.fn(),
    loadAddon: vi.fn(),
    dispose: vi.fn(),
    onData: vi.fn(),
    cols: 80,
    rows: 24,
  })),
}));
vi.mock("@xterm/xterm/css/xterm.css", () => ({}));
vi.mock("@xterm/addon-fit", () => ({ FitAddon: vi.fn(() => ({ fit: vi.fn() })) }));

import App from "../App";

describe("App", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    list.mockResolvedValue([]);
    daemonStatus.mockResolvedValue({ version: "1.2.3", pid: 1, uptime_ms: 1, sandbox_count: 0 });
  });

  it("renders the shell and reflects daemon status once polling resolves", async () => {
    render(<App />);
    // Empty-state detail pane before a sandbox is selected.
    expect(screen.getByText(/select a sandbox/i)).toBeInTheDocument();
    // TopBar flips from connecting to the resolved daemon version.
    await waitFor(() => expect(screen.getByText(/daemon running/i)).toBeInTheDocument());
    expect(screen.getByText(/v1\.2\.3/)).toBeInTheDocument();
  });
});
