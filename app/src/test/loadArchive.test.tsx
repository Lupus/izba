import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";

const { loadArchive, archiveInspect, onLoadProgress, open } = vi.hoisted(() => ({
  loadArchive: vi.fn(),
  archiveInspect: vi.fn(),
  onLoadProgress: vi.fn(),
  open: vi.fn(),
}));
vi.mock("../lib/ipc", () => ({ api: { loadArchive, archiveInspect }, onLoadProgress }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open }));

import { LoadArchive } from "../components/LoadArchive";

const archive = {
  izba_version: "0.1.0",
  source_os: "windows",
  created_unix_ms: 1_700_000_000_000,
  sandboxes: [
    { name: "web", workspace_bundled: true, source_workspace: "C:\\src\\web", locked: true },
    { name: "db", workspace_bundled: false, source_workspace: "C:\\src\\db", locked: false },
  ],
};

const loaded = {
  sandboxes: [{ name: "web", image: "ubuntu:24.04", workspace: "/home/u/web" }],
  warnings: [] as string[],
  redo: [] as string[],
};

function setup(existing: string[] = []) {
  const onClose = vi.fn();
  const onLoaded = vi.fn();
  render(<LoadArchive existing={existing} onClose={onClose} onLoaded={onLoaded} />);
  return { onClose, onLoaded };
}

const setPath = (v: string) =>
  fireEvent.change(screen.getByLabelText("Archive file"), { target: { value: v } });
const loadButton = () => screen.getByRole("button", { name: "Load" });

async function read(path = "/in/a.izba") {
  setPath(path);
  fireEvent.click(screen.getByRole("button", { name: "Read archive" }));
  await screen.findByRole("checkbox", { name: "Load web" });
}

describe("LoadArchive", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    archiveInspect.mockResolvedValue(archive);
    loadArchive.mockResolvedValue(loaded);
    onLoadProgress.mockResolvedValue(() => {});
    open.mockResolvedValue("/picked/a.izba");
  });

  it("cannot load before the archive has been read", () => {
    setup();
    expect(loadButton()).toBeDisabled();
    setPath("/in/a.izba");
    expect(loadButton()).toBeDisabled();
    expect(screen.getByText("Read the archive to see what it holds.")).toBeInTheDocument();
  });

  it("lists what the archive holds, everything selected", async () => {
    setup();
    await read();
    expect(archiveInspect).toHaveBeenCalledWith("/in/a.izba");
    expect(screen.getByRole("checkbox", { name: "Load web" })).toBeChecked();
    expect(screen.getByRole("checkbox", { name: "Load db" })).toBeChecked();
    expect(screen.getByText(/workspace included/i)).toBeInTheDocument();
    expect(screen.getByText(/workspace not included/i)).toBeInTheDocument();
    expect(screen.getByText(/was locked down/i)).toBeInTheDocument();
    expect(loadButton()).toBeEnabled();
  });

  it("reads the archive straight away when one is picked", async () => {
    setup();
    fireEvent.click(screen.getByRole("button", { name: "Browse…" }));
    await screen.findByRole("checkbox", { name: "Load web" });
    expect(archiveInspect).toHaveBeenCalledWith("/picked/a.izba");
    expect(screen.getByLabelText("Archive file")).toHaveValue("/picked/a.izba");
  });

  it("forgets the listing when the path changes", async () => {
    setup();
    await read();
    setPath("/in/other.izba");
    expect(screen.queryByRole("checkbox", { name: "Load web" })).toBeNull();
    expect(loadButton()).toBeDisabled();
  });

  it("ignores a listing that arrives for a path the user has since changed", async () => {
    let finish: (a: typeof archive) => void = () => {};
    archiveInspect.mockReturnValue(new Promise((res) => (finish = res)));
    setup();
    setPath("/in/a.izba");
    fireEvent.click(screen.getByRole("button", { name: "Read archive" }));
    setPath("/in/other.izba");
    finish(archive);
    await waitFor(() => expect(archiveInspect).toHaveBeenCalled());
    await Promise.resolve();
    expect(screen.queryByRole("checkbox", { name: "Load web" })).toBeNull();
    expect(loadButton()).toBeDisabled();
  });

  it("shows why an archive could not be read", async () => {
    archiveInspect.mockRejectedValue("not an izba archive");
    setup();
    setPath("/in/notes.txt");
    fireEvent.click(screen.getByRole("button", { name: "Read archive" }));
    expect(await screen.findByText("not an izba archive")).toBeInTheDocument();
    expect(loadButton()).toBeDisabled();
  });

  it("loads several sandboxes under one workspace parent folder", async () => {
    setup();
    await read();
    expect(screen.queryByLabelText("Load as")).toBeNull();
    fireEvent.change(screen.getByLabelText("Workspace parent folder"), {
      target: { value: "/home/u/moved" },
    });
    fireEvent.click(loadButton());
    await waitFor(() =>
      expect(loadArchive).toHaveBeenCalledWith({
        archive: "/in/a.izba",
        select: ["web", "db"],
        rename: null,
        workspace: null,
        workspace_root: "/home/u/moved",
      }),
    );
  });

  it("loads a single sandbox under a new name and workspace folder", async () => {
    setup();
    await read();
    fireEvent.click(screen.getByRole("checkbox", { name: "Load db" }));
    expect(screen.queryByLabelText("Workspace parent folder")).toBeNull();
    fireEvent.change(screen.getByLabelText("Load as"), { target: { value: "web2" } });
    fireEvent.change(screen.getByLabelText("Workspace folder"), {
      target: { value: "/home/u/web2" },
    });
    fireEvent.click(loadButton());
    await waitFor(() =>
      expect(loadArchive).toHaveBeenCalledWith({
        archive: "/in/a.izba",
        select: ["web"],
        rename: "web2",
        workspace: "/home/u/web2",
        workspace_root: null,
      }),
    );
  });

  it("does not send single-sandbox options left over from a narrower selection", async () => {
    setup();
    await read();
    fireEvent.click(screen.getByRole("checkbox", { name: "Load db" }));
    fireEvent.change(screen.getByLabelText("Load as"), { target: { value: "web2" } });
    fireEvent.click(screen.getByRole("checkbox", { name: "Load db" }));
    fireEvent.click(loadButton());
    await waitFor(() =>
      expect(loadArchive).toHaveBeenCalledWith(
        expect.objectContaining({ select: ["web", "db"], rename: null, workspace: null }),
      ),
    );
  });

  it("requires a selection", async () => {
    setup();
    await read();
    fireEvent.click(screen.getByRole("checkbox", { name: "Load web" }));
    fireEvent.click(screen.getByRole("checkbox", { name: "Load db" }));
    expect(loadButton()).toBeDisabled();
    expect(screen.getByText("Select at least one sandbox.")).toBeInTheDocument();
  });

  it("blocks a name that already exists until it is loaded under a new one", async () => {
    setup(["web"]);
    await read();
    expect(loadButton()).toBeDisabled();
    expect(screen.getByText(/web already exists/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("checkbox", { name: "Load db" }));
    expect(loadButton()).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Load as"), { target: { value: "web" } });
    expect(loadButton()).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Load as"), { target: { value: "web2" } });
    expect(loadButton()).toBeEnabled();
  });

  it("picks the workspace folder with the directory dialog", async () => {
    setup();
    await read();
    fireEvent.click(screen.getByRole("checkbox", { name: "Load db" }));
    open.mockResolvedValue("/picked/ws");
    fireEvent.click(screen.getByRole("button", { name: "Browse for workspace folder" }));
    await waitFor(() => expect(screen.getByLabelText("Workspace folder")).toHaveValue("/picked/ws"));
    expect(open).toHaveBeenLastCalledWith(expect.objectContaining({ directory: true }));
  });

  it("streams progress, then reports what arrived and what to redo", async () => {
    let push: (m: string) => void = () => {};
    onLoadProgress.mockImplementation((cb: (m: string) => void) => {
      push = cb;
      return Promise.resolve(() => {});
    });
    let finish: (r: typeof loaded) => void = () => {};
    loadArchive.mockReturnValue(new Promise((res) => (finish = res)));
    const { onLoaded } = setup();
    await read();
    fireEvent.click(loadButton());
    await waitFor(() => expect(loadArchive).toHaveBeenCalled());
    expect(screen.getByRole("button", { name: "Loading…" })).toBeDisabled();
    push("verifying checksums");
    expect(await screen.findByText("verifying checksums")).toBeInTheDocument();
    finish({
      ...loaded,
      warnings: ["host port 8080 is in use"],
      redo: ["re-run: izba lockdown web"],
    });
    expect(await screen.findByText(/Loaded 1 sandbox/)).toBeInTheDocument();
    expect(screen.getByText("/home/u/web")).toBeInTheDocument();
    expect(screen.getByText("host port 8080 is in use")).toBeInTheDocument();
    expect(screen.getByText("re-run: izba lockdown web")).toBeInTheDocument();
    expect(screen.getByText(/arrive stopped/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Done" }));
    expect(onLoaded).toHaveBeenCalledWith(["web"]);
  });

  it("surfaces a failed load and lets the user retry", async () => {
    loadArchive.mockRejectedValue("not enough free space");
    setup();
    await read();
    fireEvent.click(loadButton());
    expect(await screen.findByText("not enough free space")).toBeInTheDocument();
    expect(loadButton()).toBeEnabled();
  });
});
