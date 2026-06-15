import { render, screen, fireEvent, waitFor, cleanup } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const term = vi.hoisted(() => ({
  open: vi.fn(),
  write: vi.fn(),
  loadAddon: vi.fn(),
  dispose: vi.fn(),
  onData: vi.fn(),
  cols: 80,
  rows: 24,
}));

vi.mock("@xterm/xterm", () => ({ Terminal: vi.fn(() => term) }));
vi.mock("@xterm/xterm/css/xterm.css", () => ({}));
vi.mock("@xterm/addon-fit", () => ({ FitAddon: vi.fn(() => ({ fit: vi.fn() })) }));

let nextId = 0;
vi.mock("../lib/ipc", () => ({
  api: {
    shellOpen: vi.fn(() => Promise.resolve(`sh-${nextId++}`)),
    shellWrite: vi.fn().mockResolvedValue(undefined),
    shellResize: vi.fn().mockResolvedValue(undefined),
    shellClose: vi.fn().mockResolvedValue(undefined),
  },
  onShellOutput: vi.fn(() => Promise.resolve(() => {})),
  onShellExit: vi.fn(() => Promise.resolve(() => {})),
}));

// Stub ResizeObserver for jsdom.
class RO {
  observe() {}
  unobserve() {}
  disconnect() {}
}
(globalThis as unknown as { ResizeObserver: typeof RO }).ResizeObserver = RO;

import { ShellPanel } from "../components/ShellPanel";
import { shellStore } from "../lib/shellStore";
import { api } from "../lib/ipc";

describe("ShellPanel", () => {
  // The store is a module-level singleton. Unmount first (so closing a session
  // can't retrigger the panel's auto-open), then drain every session, before
  // resetting mock counters for the next test.
  afterEach(async () => {
    cleanup();
    for (const s of [...shellStore.snapshot()]) {
      if (s.id) await shellStore.close(s.id);
    }
  });

  beforeEach(() => {
    nextId = 0;
    vi.clearAllMocks();
  });

  it("auto-opens one session on mount when none exist", async () => {
    render(<ShellPanel sandbox="web" />);
    await waitFor(() => expect(api.shellOpen).toHaveBeenCalledWith("web"));
    await waitFor(() => expect(screen.getAllByRole("tab")).toHaveLength(1));
  });

  it("opens a second session when clicking +", async () => {
    render(<ShellPanel sandbox="web" />);
    await waitFor(() => expect(screen.getAllByRole("tab")).toHaveLength(1));
    fireEvent.click(screen.getByRole("button", { name: /new shell/i }));
    await waitFor(() => expect(screen.getAllByRole("tab")).toHaveLength(2));
    expect(api.shellOpen).toHaveBeenCalledTimes(2);
  });

  it("closes a session when clicking its ×", async () => {
    render(<ShellPanel sandbox="web" />);
    await waitFor(() => expect(screen.getAllByRole("tab")).toHaveLength(1));
    fireEvent.click(screen.getByRole("button", { name: /^close /i }));
    await waitFor(() => expect(api.shellClose).toHaveBeenCalled());
  });
});
