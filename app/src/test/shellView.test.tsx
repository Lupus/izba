import { render, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";

const term = vi.hoisted(() => ({
  open: vi.fn(),
  write: vi.fn(),
  loadAddon: vi.fn(),
  dispose: vi.fn(),
  onData: vi.fn(),
  cols: 80,
  rows: 24,
  _dataCb: null as ((d: string) => void) | null,
}));

const exitCb = vi.hoisted(() => ({ fn: null as (() => void) | null }));

vi.mock("@xterm/xterm", () => ({
  Terminal: vi.fn(() => {
    term.onData.mockImplementation((cb: (d: string) => void) => {
      term._dataCb = cb;
    });
    return term;
  }),
}));
vi.mock("@xterm/addon-fit", () => ({
  FitAddon: vi.fn(() => ({ fit: vi.fn() })),
}));
vi.mock("../lib/ipc", () => ({
  api: {
    shellOpen: vi.fn().mockResolvedValue(undefined),
    shellWrite: vi.fn().mockResolvedValue(undefined),
    shellResize: vi.fn().mockResolvedValue(undefined),
    shellClose: vi.fn().mockResolvedValue(undefined),
  },
  onShellOutput: vi.fn(() => Promise.resolve(() => {})),
  onShellExit: vi.fn((_name: string, cb: () => void) => {
    exitCb.fn = cb;
    return Promise.resolve(() => {});
  }),
}));

import { ShellView } from "../components/ShellView";

describe("ShellView", () => {
  beforeEach(() => vi.clearAllMocks());

  it("opens a shell on mount and subscribes to output", async () => {
    const { api, onShellOutput } = await import("../lib/ipc");
    render(<ShellView name="web" />);
    await waitFor(() => expect(api.shellOpen).toHaveBeenCalledWith("web"));
    expect(onShellOutput).toHaveBeenCalled();
  });

  it("forwards keystrokes to shellWrite", async () => {
    const { api } = await import("../lib/ipc");
    render(<ShellView name="web" />);
    await waitFor(() => expect(term.onData).toHaveBeenCalled());
    term._dataCb?.("x");
    expect(api.shellWrite).toHaveBeenCalledWith("web", "x");
  });

  it("closes the shell on unmount", async () => {
    const { api } = await import("../lib/ipc");
    const { unmount } = render(<ShellView name="web" />);
    await waitFor(() => expect(api.shellOpen).toHaveBeenCalled());
    unmount();
    expect(api.shellClose).toHaveBeenCalledWith("web");
  });

  it("closes the shell when the process exits", async () => {
    const { api } = await import("../lib/ipc");
    render(<ShellView name="web" />);
    await waitFor(() => expect(exitCb.fn).not.toBeNull());
    exitCb.fn?.();
    expect(api.shellClose).toHaveBeenCalledWith("web");
  });
});
