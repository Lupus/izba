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

import { shellStore } from "../lib/shellStore";
import { api } from "../lib/ipc";

describe("shellStore", () => {
  beforeEach(() => {
    nextId = 0;
    vi.clearAllMocks();
  });

  // The store is a module-level singleton; close any leftover sessions.
  afterEach(async () => {
    for (const s of [...shellStore.snapshot()]) {
      if (s.id) await shellStore.close(s.id);
    }
  });

  it("open pushes a session, calls api.shellOpen, and assigns the returned id", async () => {
    await shellStore.open("web");
    expect(api.shellOpen).toHaveBeenCalledWith("web");
    const got = shellStore.forSandbox("web");
    expect(got).toHaveLength(1);
    expect(got[0].id).toBe("sh-0");
  });

  it("forSandbox returns only that sandbox's sessions", async () => {
    await shellStore.open("web");
    await shellStore.open("api");
    expect(shellStore.forSandbox("web")).toHaveLength(1);
    expect(shellStore.forSandbox("api")).toHaveLength(1);
  });

  it("close calls api.shellClose, disposes the term, and removes the session", async () => {
    await shellStore.open("web");
    const id = shellStore.forSandbox("web")[0].id;
    await shellStore.close(id);
    expect(api.shellClose).toHaveBeenCalledWith(id);
    expect(term.dispose).toHaveBeenCalled();
    expect(shellStore.snapshot().some((s) => s.id === id)).toBe(false);
  });
});
