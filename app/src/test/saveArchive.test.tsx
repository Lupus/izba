import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import type { SandboxView } from "../lib/types";

const { saveArchive, onSaveProgress, save } = vi.hoisted(() => ({
  saveArchive: vi.fn(),
  onSaveProgress: vi.fn(),
  save: vi.fn(),
}));
vi.mock("../lib/ipc", () => ({ api: { saveArchive }, onSaveProgress }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ save }));

import { SaveArchive } from "../components/SaveArchive";

const sandboxes: SandboxView[] = [
  { name: "web", image: "ubuntu:24.04", state: { kind: "running" } },
  { name: "db", image: "postgres:16", state: { kind: "stopped" } },
];

const report = {
  path: "/backups/db.izba",
  sandboxes: ["db"],
  logical_bytes: 2048,
  archive_bytes: 1024,
  warnings: [] as string[],
};

function setup(initial: string | null = "db") {
  const onClose = vi.fn();
  const onSaved = vi.fn();
  render(
    <SaveArchive sandboxes={sandboxes} initial={initial} onClose={onClose} onSaved={onSaved} />,
  );
  return { onClose, onSaved };
}

const setPath = (v: string) =>
  fireEvent.change(screen.getByLabelText("Archive file"), { target: { value: v } });
const saveButton = () => screen.getByRole("button", { name: "Save" });

describe("SaveArchive", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    saveArchive.mockResolvedValue(report);
    onSaveProgress.mockResolvedValue(() => {});
    save.mockResolvedValue("/picked/db.izba");
  });

  it("preselects the current sandbox and saves it to the typed path", async () => {
    setup("db");
    expect(screen.getByRole("checkbox", { name: "Save db" })).toBeChecked();
    expect(screen.getByRole("checkbox", { name: "Save web" })).not.toBeChecked();
    setPath("/backups/db.izba");
    fireEvent.click(saveButton());
    await waitFor(() =>
      expect(saveArchive).toHaveBeenCalledWith({
        names: ["db"],
        out: "/backups/db.izba",
        with_workspace: false,
        stop: false,
        overwrite: false,
      }),
    );
  });

  it("keeps Save disabled until a sandbox and a file are chosen", () => {
    setup(null);
    expect(saveButton()).toBeDisabled();
    expect(screen.getByText("Select at least one sandbox.")).toBeInTheDocument();
    expect(screen.getByText("Choose where to save the archive.")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("checkbox", { name: "Save db" }));
    expect(saveButton()).toBeDisabled();
    setPath("/backups/db.izba");
    expect(saveButton()).toBeEnabled();
  });

  it("includes the workspace folders when asked", async () => {
    setup("db");
    setPath("/backups/db.izba");
    fireEvent.click(screen.getByRole("checkbox", { name: "Include workspace folders" }));
    fireEvent.click(saveButton());
    await waitFor(() =>
      expect(saveArchive).toHaveBeenCalledWith(expect.objectContaining({ with_workspace: true })),
    );
  });

  it("offers the stop option only while a running sandbox is selected", () => {
    setup("db");
    expect(screen.queryByRole("checkbox", { name: /stop running sandboxes/i })).toBeNull();
    fireEvent.click(screen.getByRole("checkbox", { name: "Save web" }));
    expect(screen.getByRole("checkbox", { name: /stop running sandboxes/i })).toBeInTheDocument();
  });

  it("will not save a running sandbox until the user agrees to stop it", async () => {
    setup("web");
    setPath("/backups/web.izba");
    expect(saveButton()).toBeDisabled();
    expect(screen.getByText(/web is running/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("checkbox", { name: /stop running sandboxes/i }));
    expect(saveButton()).toBeEnabled();
    fireEvent.click(saveButton());
    await waitFor(() =>
      expect(saveArchive).toHaveBeenCalledWith(
        expect.objectContaining({ names: ["web"], stop: true }),
      ),
    );
  });

  it("does not carry a stale stop consent over to a selection with nothing running", async () => {
    setup("web");
    setPath("/backups/x.izba");
    fireEvent.click(screen.getByRole("checkbox", { name: /stop running sandboxes/i }));
    fireEvent.click(screen.getByRole("checkbox", { name: "Save web" }));
    fireEvent.click(screen.getByRole("checkbox", { name: "Save db" }));
    fireEvent.click(saveButton());
    await waitFor(() =>
      expect(saveArchive).toHaveBeenCalledWith(
        expect.objectContaining({ names: ["db"], stop: false }),
      ),
    );
  });

  it("treats a file picked in the save dialog as confirmed for replacement", async () => {
    setup("db");
    fireEvent.click(screen.getByRole("button", { name: "Browse…" }));
    await waitFor(() => expect(screen.getByLabelText("Archive file")).toHaveValue("/picked/db.izba"));
    expect(save).toHaveBeenCalledWith(
      expect.objectContaining({ defaultPath: "db.izba" }),
    );
    fireEvent.click(saveButton());
    await waitFor(() =>
      expect(saveArchive).toHaveBeenCalledWith(
        expect.objectContaining({ out: "/picked/db.izba", overwrite: true }),
      ),
    );
  });

  it("drops the replacement consent once the picked path is edited", async () => {
    setup("db");
    fireEvent.click(screen.getByRole("button", { name: "Browse…" }));
    await waitFor(() => expect(screen.getByLabelText("Archive file")).toHaveValue("/picked/db.izba"));
    setPath("/picked/other.izba");
    fireEvent.click(saveButton());
    await waitFor(() =>
      expect(saveArchive).toHaveBeenCalledWith(
        expect.objectContaining({ out: "/picked/other.izba", overwrite: false }),
      ),
    );
  });

  it("leaves the path alone when the save dialog is cancelled", async () => {
    save.mockResolvedValue(null);
    setup("db");
    setPath("/typed.izba");
    fireEvent.click(screen.getByRole("button", { name: "Browse…" }));
    await waitFor(() => expect(save).toHaveBeenCalled());
    expect(screen.getByLabelText("Archive file")).toHaveValue("/typed.izba");
  });

  it("streams progress, then reports what was written", async () => {
    let push: (m: string) => void = () => {};
    onSaveProgress.mockImplementation((cb: (m: string) => void) => {
      push = cb;
      return Promise.resolve(() => {});
    });
    let finish: (r: typeof report) => void = () => {};
    saveArchive.mockReturnValue(new Promise((res) => (finish = res)));
    const { onSaved } = setup("db");
    setPath("/backups/db.izba");
    fireEvent.click(saveButton());
    await waitFor(() => expect(saveArchive).toHaveBeenCalled());
    expect(screen.getByRole("button", { name: "Saving…" })).toBeDisabled();
    push("archiving 'db'");
    expect(await screen.findByText("archiving 'db'")).toBeInTheDocument();
    finish({ ...report, warnings: ["skipped socket run.sock"] });
    expect(await screen.findByText(/Saved 1 sandbox to/)).toBeInTheDocument();
    expect(screen.getByText("/backups/db.izba")).toBeInTheDocument();
    expect(screen.getByText(/1\.0 KiB archive/)).toBeInTheDocument();
    expect(screen.getByText("skipped socket run.sock")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Done" }));
    expect(onSaved).toHaveBeenCalled();
  });

  it("surfaces a failed save and lets the user retry", async () => {
    saveArchive.mockRejectedValue("/backups/db.izba already exists — choose another name");
    setup("db");
    setPath("/backups/db.izba");
    fireEvent.click(saveButton());
    expect(await screen.findByText(/already exists/)).toBeInTheDocument();
    expect(saveButton()).toBeEnabled();
  });

  it("asks again before stopping when the selection changes", () => {
    render(
      <SaveArchive
        sandboxes={[...sandboxes, { name: "api", image: "node:22", state: { kind: "running" } }]}
        initial="web"
        onClose={() => {}}
        onSaved={() => {}}
      />,
    );
    setPath("/backups/x.izba");
    const stop = () => screen.getByRole("checkbox", { name: /stop running sandboxes/i });
    fireEvent.click(stop());
    expect(saveButton()).toBeEnabled();
    // Consent was for stopping web; api was not part of it.
    fireEvent.click(screen.getByRole("checkbox", { name: "Save api" }));
    expect(stop()).not.toBeChecked();
    expect(saveButton()).toBeDisabled();
  });

  it("cannot be dismissed while the save is running", async () => {
    saveArchive.mockReturnValue(new Promise(() => {}));
    const { onClose } = setup("db");
    setPath("/backups/db.izba");
    fireEvent.click(saveButton());
    await waitFor(() => expect(saveArchive).toHaveBeenCalled());
    expect(screen.getByRole("button", { name: "Cancel" })).toBeDisabled();
    fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });
    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    expect(onClose).not.toHaveBeenCalled();
    expect(screen.getByRole("dialog", { name: "Save sandboxes" })).toBeInTheDocument();
  });
});
