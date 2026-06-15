import { render, screen, fireEvent, waitFor, cleanup } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import React from "react";

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

vi.mock("../lib/ipc", () => ({
  api: {
    shellOpen: vi.fn().mockResolvedValue(undefined),
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
    vi.clearAllMocks();
  });

  it("auto-opens one session on mount when none exist", async () => {
    render(<ShellPanel sandbox="web" />);
    await waitFor(() => expect(api.shellOpen).toHaveBeenCalledWith("web", expect.any(String)));
    await waitFor(() => expect(screen.getAllByRole("tab")).toHaveLength(1));
  });

  it("auto-opens exactly once under StrictMode (double-invoke guard)", async () => {
    render(
      <React.StrictMode>
        <ShellPanel sandbox="web" />
      </React.StrictMode>,
    );
    await waitFor(() => expect(screen.getAllByRole("tab")).toHaveLength(1));
    expect(api.shellOpen).toHaveBeenCalledTimes(1);
  });

  it("clips the terminal host so a shrink can't leak a page-level scrollbar", async () => {
    // Regression: on window shrink, xterm parks its absolutely-positioned helper
    // textarea at the old cursor pixel `top`, inflating scrollHeight up the flex
    // chain unless the host clips. jsdom has no layout, so guard the contract:
    // the host that xterm is opened into must hide overflow.
    render(<ShellPanel sandbox="web" />);
    const host = await screen.findByTestId("shell-host");
    expect(host.className).toContain("overflow-hidden");
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

  it("closing the last shell shows the empty state and does NOT reopen", async () => {
    render(<ShellPanel sandbox="web" />);
    await waitFor(() => expect(screen.getAllByRole("tab")).toHaveLength(1));
    expect(api.shellOpen).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole("button", { name: /^close /i }));
    await waitFor(() => expect(screen.queryAllByRole("tab")).toHaveLength(0));
    // The empty-state hint replaces the viewer; auto-open does NOT re-fire.
    expect(screen.getByText(/no shells/i)).toBeTruthy();
    expect(api.shellOpen).toHaveBeenCalledTimes(1);
  });
});
