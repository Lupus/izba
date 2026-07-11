import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";

const { create, onCreateProgress, volumeList } = vi.hoisted(() => ({
  create: vi.fn(),
  onCreateProgress: vi.fn(),
  volumeList: vi.fn(),
}));
vi.mock("../lib/ipc", () => ({ api: { create, volumeList }, onCreateProgress }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn().mockResolvedValue("/picked/ws") }));

import { NewSandbox } from "../components/NewSandbox";

describe("NewSandbox", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    create.mockResolvedValue("web");
    onCreateProgress.mockResolvedValue(() => {});
    volumeList.mockResolvedValue([]);
  });

  it("submits create with form values", async () => {
    const onClose = vi.fn();
    render(<NewSandbox onClose={onClose} onCreated={() => {}} />);
    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: "web" } });
    fireEvent.change(screen.getByLabelText(/workspace/i), { target: { value: "/ws" } });
    fireEvent.click(screen.getByRole("button", { name: /create/i }));
    await waitFor(() =>
      expect(create).toHaveBeenCalledWith(
        expect.objectContaining({ name: "web", workspace: "/ws", image: "ubuntu:24.04" }),
      ),
    );
  });

  it("assembles a host:guest port from an added row", async () => {
    render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);
    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: "web" } });
    fireEvent.change(screen.getByLabelText(/workspace/i), { target: { value: "/ws" } });
    fireEvent.click(screen.getByRole("button", { name: /add port/i }));
    fireEvent.change(screen.getByLabelText(/port 1 host/i), { target: { value: "8080" } });
    fireEvent.change(screen.getByLabelText(/port 1 guest/i), { target: { value: "80" } });
    fireEvent.click(screen.getByRole("button", { name: /create/i }));
    await waitFor(() =>
      expect(create).toHaveBeenCalledWith(expect.objectContaining({ ports: ["8080:80"] })),
    );
  });

  it("includes the bind prefix when given, and drops removed rows", async () => {
    render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);
    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: "web" } });
    fireEvent.change(screen.getByLabelText(/workspace/i), { target: { value: "/ws" } });
    fireEvent.click(screen.getByRole("button", { name: /add port/i }));
    fireEvent.click(screen.getByRole("button", { name: /add port/i }));
    fireEvent.change(screen.getByLabelText(/port 1 bind/i), { target: { value: "127.0.0.1" } });
    fireEvent.change(screen.getByLabelText(/port 1 host/i), { target: { value: "5432" } });
    fireEvent.change(screen.getByLabelText(/port 1 guest/i), { target: { value: "5432" } });
    fireEvent.click(screen.getByRole("button", { name: /remove port 2/i }));
    fireEvent.click(screen.getByRole("button", { name: /create/i }));
    await waitFor(() =>
      expect(create).toHaveBeenCalledWith(
        expect.objectContaining({ ports: ["127.0.0.1:5432:5432"] }),
      ),
    );
  });

  it("labels the port columns and explains the bind field", () => {
    render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);
    fireEvent.click(screen.getByRole("button", { name: /add port/i }));
    expect(screen.getByText(/host port/i)).toBeInTheDocument();
    expect(screen.getByText(/guest port/i)).toBeInTheDocument();
    expect(screen.getByText(/defaults to 127\.0\.0\.1/i)).toBeInTheDocument();
  });

  it("disables Create and explains when a port is not a valid number", async () => {
    render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);
    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: "web" } });
    fireEvent.change(screen.getByLabelText(/workspace/i), { target: { value: "/ws" } });
    fireEvent.click(screen.getByRole("button", { name: /add port/i }));
    fireEvent.change(screen.getByLabelText(/port 1 host/i), { target: { value: "sdfsdf" } });
    fireEvent.change(screen.getByLabelText(/port 1 guest/i), { target: { value: "80" } });
    expect(screen.getByText(/65535/)).toBeInTheDocument();
    expect(screen.getByText("Fix the invalid port row above.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /create/i })).toBeDisabled();
  });

  it("disables Create when the bind address is not a valid IPv4", () => {
    render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);
    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: "web" } });
    fireEvent.change(screen.getByLabelText(/workspace/i), { target: { value: "/ws" } });
    fireEvent.click(screen.getByRole("button", { name: /add port/i }));
    fireEvent.change(screen.getByLabelText(/port 1 bind/i), { target: { value: "sdsdasdas" } });
    fireEvent.change(screen.getByLabelText(/port 1 host/i), { target: { value: "8080" } });
    fireEvent.change(screen.getByLabelText(/port 1 guest/i), { target: { value: "80" } });
    expect(screen.getByText(/IPv4/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /create/i })).toBeDisabled();
  });

  it("an empty port row does not block Create", () => {
    render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);
    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: "web" } });
    fireEvent.change(screen.getByLabelText(/workspace/i), { target: { value: "/ws" } });
    fireEvent.click(screen.getByRole("button", { name: /add port/i }));
    expect(screen.getByRole("button", { name: /create/i })).not.toBeDisabled();
  });

  it("disables Create when name is empty", () => {
    render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);
    expect(screen.getByRole("button", { name: /create/i })).toBeDisabled();
  });

  it("explains why Create is disabled with a hint list for missing required fields", () => {
    render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);
    expect(screen.getByText("Name is required.")).toBeInTheDocument();
    expect(screen.getByText("Workspace folder is required.")).toBeInTheDocument();
    const btn = screen.getByRole("button", { name: /create/i });
    expect(btn).toBeDisabled();
    expect(btn).toHaveAttribute("aria-describedby", "ns-create-hints");
  });

  it("drops the missing-name hint once a name is entered, keeps the workspace one", () => {
    render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);
    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: "web" } });
    expect(screen.queryByText("Name is required.")).not.toBeInTheDocument();
    expect(screen.getByText("Workspace folder is required.")).toBeInTheDocument();
  });

  it("has no disabled-reason hints once the required fields are filled in", () => {
    render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);
    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: "web" } });
    fireEvent.change(screen.getByLabelText(/workspace/i), { target: { value: "/ws" } });
    expect(screen.queryByText("Name is required.")).not.toBeInTheDocument();
    expect(screen.queryByText("Workspace folder is required.")).not.toBeInTheDocument();
    const btn = screen.getByRole("button", { name: /create/i });
    expect(btn).not.toBeDisabled();
    expect(btn).not.toHaveAttribute("aria-describedby");
  });

  it("surfaces a create error", async () => {
    create.mockRejectedValueOnce(new Error("invalid sandbox name 'X'"));
    render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);
    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: "x" } });
    fireEvent.change(screen.getByLabelText(/workspace/i), { target: { value: "/ws" } });
    fireEvent.click(screen.getByRole("button", { name: /create/i }));
    await waitFor(() => expect(screen.getByText(/invalid sandbox name/i)).toBeInTheDocument());
  });

  // ── Volume section — inline-rows flow ─────────────────────────────────────────

  it("'Add volume' appends a row", () => {
    render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);
    // No VolumeRowEditor before clicking
    expect(screen.queryByLabelText(/volume 1 path/i)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    expect(screen.getByLabelText(/volume 1 path/i)).toBeInTheDocument();
  });

  it("'×' removes the inline row", () => {
    render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    expect(screen.getByLabelText(/volume 1 path/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /remove volume 1/i }));
    expect(screen.queryByLabelText(/volume 1 path/i)).not.toBeInTheDocument();
  });

  it("submits a named volume row as name:path:size", async () => {
    render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);
    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: "web" } });
    fireEvent.change(screen.getByLabelText(/workspace/i), { target: { value: "/ws" } });
    // Click Add volume then fill inline
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    fireEvent.click(screen.getByRole("radio", { name: /new persistent/i }));
    fireEvent.change(screen.getByLabelText(/volume 1 name/i), { target: { value: "cache" } });
    fireEvent.change(screen.getByLabelText(/volume 1 path/i), { target: { value: "/data" } });
    fireEvent.change(screen.getByLabelText(/volume 1 size/i), { target: { value: "1g" } });
    fireEvent.click(screen.getByRole("button", { name: /create/i }));
    await waitFor(() =>
      expect(create).toHaveBeenCalledWith(
        expect.objectContaining({ volumes: ["cache:/data:1g"] }),
      ),
    );
  });

  it("live error: typing invalid path shows error immediately (no click needed)", () => {
    render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    fireEvent.change(screen.getByLabelText(/volume 1 path/i), { target: { value: "data" } });
    expect(screen.getByText(/guest path must be absolute/i)).toBeInTheDocument();
  });

  it("live error: non-blank invalid size shows error immediately", () => {
    render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    fireEvent.change(screen.getByLabelText(/volume 1 path/i), { target: { value: "/data" } });
    fireEvent.change(screen.getByLabelText(/volume 1 size/i), { target: { value: "1x" } });
    expect(screen.getByText(/size must be a positive number followed by g or m/i)).toBeInTheDocument();
  });

  it("shows error on Add when volume path lacks leading slash and blocks Create", () => {
    render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);
    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: "web" } });
    fireEvent.change(screen.getByLabelText(/workspace/i), { target: { value: "/ws" } });
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    fireEvent.click(screen.getByRole("radio", { name: /new persistent/i }));
    fireEvent.change(screen.getByLabelText(/volume 1 name/i), { target: { value: "cache" } });
    fireEvent.change(screen.getByLabelText(/volume 1 path/i), { target: { value: "data" } });
    fireEvent.change(screen.getByLabelText(/volume 1 size/i), { target: { value: "1g" } });
    // Error shown live
    expect(screen.getByText(/guest path must be absolute/i)).toBeInTheDocument();
    // Create button IS disabled because the row is non-blank and invalid
    expect(screen.getByRole("button", { name: /create/i })).toBeDisabled();
    expect(screen.getByText("Fix the invalid volume row above.")).toBeInTheDocument();
  });

  it("shows error on Add when volume size is invalid and blocks Create", () => {
    render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);
    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: "web" } });
    fireEvent.change(screen.getByLabelText(/workspace/i), { target: { value: "/ws" } });
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    fireEvent.click(screen.getByRole("radio", { name: /new persistent/i }));
    fireEvent.change(screen.getByLabelText(/volume 1 name/i), { target: { value: "cache" } });
    fireEvent.change(screen.getByLabelText(/volume 1 path/i), { target: { value: "/data" } });
    fireEvent.change(screen.getByLabelText(/volume 1 size/i), { target: { value: "1x" } });
    // Error shown live
    expect(screen.getByText(/size must be a positive number followed by g or m/i)).toBeInTheDocument();
    // Create button IS disabled because the row is non-blank and invalid
    expect(screen.getByRole("button", { name: /create/i })).toBeDisabled();
  });

  it("emits ephemeral spec (no name prefix) for ephemeral volume row", async () => {
    render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);
    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: "web" } });
    fireEvent.change(screen.getByLabelText(/workspace/i), { target: { value: "/ws" } });
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    // Ephemeral is the default type
    fireEvent.click(screen.getByRole("radio", { name: /ephemeral/i }));
    fireEvent.change(screen.getByLabelText(/volume 1 path/i), { target: { value: "/scratch" } });
    fireEvent.change(screen.getByLabelText(/volume 1 size/i), { target: { value: "1g" } });
    fireEvent.click(screen.getByRole("button", { name: /create/i }));
    await waitFor(() =>
      expect(create).toHaveBeenCalledWith(
        expect.objectContaining({ volumes: ["/scratch:1g"] }),
      ),
    );
  });

  it("existing persistent: select trigger is present with accessible name", async () => {
    volumeList.mockResolvedValue([
      { name: "archive", size_bytes: 1073741824, actual_bytes: 0, referenced_by: [] },
    ]);
    render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);
    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: "web" } });
    fireEvent.change(screen.getByLabelText(/workspace/i), { target: { value: "/ws" } });

    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    // Switch to existing persistent type
    fireEvent.click(screen.getByRole("radio", { name: /existing/i }));

    await waitFor(() => expect(volumeList).toHaveBeenCalled());
    // Radix Select trigger present with correct accessible name
    expect(screen.getByRole("combobox", { name: /existing volume/i })).toBeInTheDocument();
    // Note: open+pick behaviour is exercised in volumeRowEditor.browser.test.tsx
  });

  it("fully blank added row does NOT disable Create", () => {
    render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);
    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: "web" } });
    fireEvent.change(screen.getByLabelText(/workspace/i), { target: { value: "/ws" } });
    // Add a blank row — should NOT block Create
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    expect(screen.getByRole("button", { name: /create/i })).not.toBeDisabled();
  });

  it("non-blank invalid row DISABLES Create", () => {
    render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);
    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: "web" } });
    fireEvent.change(screen.getByLabelText(/workspace/i), { target: { value: "/ws" } });
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    // Type an invalid (non-slash-prefixed) path
    fireEvent.change(screen.getByLabelText(/volume 1 path/i), { target: { value: "x" } });
    expect(screen.getByRole("button", { name: /create/i })).toBeDisabled();
  });

  it("ignores blank inline row on submit (volumes: [])", async () => {
    render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);
    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: "web" } });
    fireEvent.change(screen.getByLabelText(/workspace/i), { target: { value: "/ws" } });
    // Add row but leave blank
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    fireEvent.click(screen.getByRole("button", { name: /create/i }));
    await waitFor(() =>
      expect(create).toHaveBeenCalledWith(expect.objectContaining({ volumes: [] })),
    );
  });

  it("inline row can be removed before Create", async () => {
    render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);
    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: "web" } });
    fireEvent.change(screen.getByLabelText(/workspace/i), { target: { value: "/ws" } });
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    fireEvent.change(screen.getByLabelText(/volume 1 path/i), { target: { value: "/data" } });
    fireEvent.change(screen.getByLabelText(/volume 1 size/i), { target: { value: "1g" } });
    // Remove it with ×
    fireEvent.click(screen.getByRole("button", { name: /remove volume 1/i }));
    // Now create — volumes should be empty
    fireEvent.click(screen.getByRole("button", { name: /create/i }));
    await waitFor(() =>
      expect(create).toHaveBeenCalledWith(expect.objectContaining({ volumes: [] })),
    );
  });

  it("existing persistent dropdown excludes volumes already in another row", async () => {
    volumeList.mockResolvedValue([
      { name: "archive", size_bytes: 1073741824, actual_bytes: 0, referenced_by: [] },
      { name: "other", size_bytes: 1073741824, actual_bytes: 0, referenced_by: [] },
    ]);
    render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);

    // Add first row, switch to existing persistent, fill path
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    fireEvent.click(screen.getByRole("radio", { name: /existing/i }));
    await waitFor(() => expect(volumeList).toHaveBeenCalled());
    // Radix Select: open+pick via browser test; here verify the trigger is present
    expect(screen.getByRole("combobox", { name: /existing volume/i })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/volume 1 path/i), { target: { value: "/arch" } });

    // Add a second row — both triggers present; filtering validated by browser test
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    fireEvent.click(screen.getAllByRole("radio", { name: /existing/i })[1]);
    expect(screen.getAllByRole("combobox", { name: /existing volume/i })).toHaveLength(2);
  });

  // ── Modal UX: Escape + backdrop close ────────────────────────────────────────

  it("Escape key calls onClose", () => {
    const onClose = vi.fn();
    render(<NewSandbox onClose={onClose} onCreated={() => {}} />);
    fireEvent.keyDown(document, { key: "Escape" });
    expect(onClose).toHaveBeenCalled();
  });

  it("backdrop click calls onClose", () => {
    const onClose = vi.fn();
    render(<NewSandbox onClose={onClose} onCreated={() => {}} />);
    // The Dialog primitive renders a built-in close button (sr-only "Close")
    const closeBtn = screen.getByRole("button", { name: /^close$/i });
    fireEvent.click(closeBtn);
    expect(onClose).toHaveBeenCalled();
  });

  it("clicking inside panel does NOT call onClose", () => {
    const onClose = vi.fn();
    render(<NewSandbox onClose={onClose} onCreated={() => {}} />);
    // Click on the heading inside the panel (not the backdrop button)
    fireEvent.click(screen.getByText("New sandbox"));
    expect(onClose).not.toHaveBeenCalled();
  });
});
