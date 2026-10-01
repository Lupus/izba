import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";

const { list, daemonStatus, loadArchive, archiveInspect } = vi.hoisted(() => ({
  list: vi.fn(),
  daemonStatus: vi.fn(),
  loadArchive: vi.fn(),
  archiveInspect: vi.fn(),
}));
vi.mock("../lib/ipc", () => ({
  api: { list, daemonStatus, loadArchive, archiveInspect },
  onCreateProgress: vi.fn(() => Promise.resolve(() => {})),
  onSaveProgress: vi.fn(() => Promise.resolve(() => {})),
  onLoadProgress: vi.fn(() => Promise.resolve(() => {})),
}));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn(), save: vi.fn() }));
// The detail pane is not under test here (it needs the whole IPC surface);
// a stub that names the sandbox it was handed is all the wiring checks need.
vi.mock("../components/Detail", () => ({
  Detail: ({ sandbox }: { sandbox: { name: string } | null }) => (
    <div data-testid="detail">{sandbox ? sandbox.name : "none"}</div>
  ),
}));

import App from "../App";

const sandboxes = [
  { name: "web", image: "ubuntu:24.04", state: { kind: "stopped" } },
  { name: "db", image: "postgres:16", state: { kind: "stopped" } },
];

describe("App save/load archive wiring", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    list.mockResolvedValue(sandboxes);
    daemonStatus.mockResolvedValue({ version: "1.2.3", pid: 1, uptime_ms: 1, sandbox_count: 2 });
  });

  it("opens the Save dialog with the selected sandbox preselected", async () => {
    render(<App />);
    fireEvent.click(await screen.findByText("db"));
    fireEvent.click(screen.getByRole("button", { name: "Save archive" }));
    expect(await screen.findByRole("dialog", { name: "Save sandboxes" })).toBeInTheDocument();
    expect(screen.getByRole("checkbox", { name: "Save db" })).toBeChecked();
    expect(screen.getByRole("checkbox", { name: "Save web" })).not.toBeChecked();
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await waitFor(() =>
      expect(screen.queryByRole("dialog", { name: "Save sandboxes" })).toBeNull(),
    );
  });

  it("selects the first loaded sandbox once a load is dismissed", async () => {
    archiveInspect.mockResolvedValue({
      izba_version: "0.1.0",
      source_os: "linux",
      created_unix_ms: 1,
      sandboxes: [
        { name: "api", workspace_bundled: true, source_workspace: "/src/api", locked: false },
      ],
    });
    loadArchive.mockResolvedValue({
      sandboxes: [{ name: "api", image: "node:22", workspace: "/home/u/api" }],
      warnings: [],
      redo: [],
    });
    render(<App />);
    await screen.findByText("db");
    fireEvent.click(screen.getByRole("button", { name: "Load archive" }));
    await screen.findByRole("dialog", { name: "Load sandboxes" });
    fireEvent.change(screen.getByLabelText("Archive file"), { target: { value: "/in/a.izba" } });
    fireEvent.click(screen.getByRole("button", { name: "Read archive" }));
    await screen.findByRole("checkbox", { name: "Load api" });
    // The freshly loaded sandbox shows up on the next poll.
    list.mockResolvedValue([
      ...sandboxes,
      { name: "api", image: "node:22", state: { kind: "stopped" } },
    ]);
    fireEvent.click(screen.getByRole("button", { name: "Load" }));
    fireEvent.click(await screen.findByRole("button", { name: "Done" }));
    await waitFor(() => expect(screen.getByTestId("detail")).toHaveTextContent("api"));
    expect(screen.queryByRole("dialog", { name: "Load sandboxes" })).toBeNull();
  });

  it("refuses in the dialog a name the host already has", async () => {
    archiveInspect.mockResolvedValue({
      izba_version: "0.1.0",
      source_os: "linux",
      created_unix_ms: 1,
      sandboxes: [
        { name: "web", workspace_bundled: true, source_workspace: "/src/web", locked: false },
      ],
    });
    render(<App />);
    await screen.findByText("db");
    fireEvent.click(screen.getByRole("button", { name: "Load archive" }));
    fireEvent.change(await screen.findByLabelText("Archive file"), {
      target: { value: "/in/a.izba" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Read archive" }));
    expect(await screen.findByText(/web already exists/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Load" })).toBeDisabled();
  });
});
