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

import { shellStore } from "../lib/shellStore";
import { api, onShellOutput, onShellExit } from "../lib/ipc";

describe("shellStore", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // The store is a module-level singleton; close any leftover sessions.
  afterEach(async () => {
    for (const s of [...shellStore.snapshot()]) {
      if (s.id) await shellStore.close(s.id);
    }
  });

  it("open mints a client id, subscribes BEFORE opening, then calls api.shellOpen", async () => {
    const id = await shellStore.open("web");
    // Client-minted, deterministic counter id; passed to the backend.
    expect(id).toMatch(/^sh-\d+$/);
    expect(api.shellOpen).toHaveBeenCalledWith("web", id);
    // Subscriptions are wired to the id before the backend open.
    expect(onShellOutput).toHaveBeenCalledWith(id, expect.any(Function));
    expect(onShellExit).toHaveBeenCalledWith(id, expect.any(Function));
    const onOutOrder = (onShellOutput as ReturnType<typeof vi.fn>).mock.invocationCallOrder[0];
    const openOrder = (api.shellOpen as ReturnType<typeof vi.fn>).mock.invocationCallOrder[0];
    expect(onOutOrder).toBeLessThan(openOrder);
    const got = shellStore.forSandbox("web");
    expect(got).toHaveLength(1);
    expect(got[0].id).toBe(id);
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

  it("remembers the active session per sandbox, independently", async () => {
    const a = await shellStore.open("web");
    await shellStore.open("web");
    await shellStore.open("api");
    shellStore.setActive("web", a);
    expect(shellStore.getActive("web")).toBe(a);
    // A sandbox with no explicit selection has no remembered active id.
    expect(shellStore.getActive("api")).toBeUndefined();
  });

  it("forgets the active id when that session is closed", async () => {
    const a = await shellStore.open("web");
    shellStore.setActive("web", a);
    await shellStore.close(a);
    expect(shellStore.getActive("web")).toBeUndefined();
  });
});
