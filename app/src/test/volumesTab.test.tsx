import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach } from "vitest";
import type { SandboxView, SandboxDetail } from "../lib/types";

// ── hoisted mocks ─────────────────────────────────────────────────────────────

const { inspect, volumeAttach, volumeDetach, restart, volumeList } = vi.hoisted(() => ({
  inspect: vi.fn(),
  volumeAttach: vi.fn(),
  volumeDetach: vi.fn(),
  restart: vi.fn(),
  volumeList: vi.fn(),
}));

vi.mock("../lib/ipc", () => ({
  api: { inspect, volumeAttach, volumeDetach, restart, volumeList },
}));

import { VolumesTab } from "../components/VolumesTab";

// ── helpers ───────────────────────────────────────────────────────────────────

const running: SandboxView = {
  name: "mysbx",
  image: "ubuntu:24.04",
  state: { kind: "running" },
};
const stopped: SandboxView = {
  name: "mysbx",
  image: "ubuntu:24.04",
  state: { kind: "stopped" },
};

function makeDetail(overrides: Partial<SandboxDetail> = {}): SandboxDetail {
  return {
    name: "mysbx",
    image: "ubuntu:24.04",
    status: "running",
    ports: [],
    volumes: [],
    ...overrides,
  };
}

const noop = () => {};

beforeEach(() => {
  vi.clearAllMocks();
  inspect.mockResolvedValue(makeDetail());
  volumeAttach.mockResolvedValue(undefined);
  volumeDetach.mockResolvedValue(undefined);
  restart.mockResolvedValue(undefined);
  volumeList.mockResolvedValue([]);
});

// ── tests ─────────────────────────────────────────────────────────────────────

describe("VolumesTab — seeding from inspect", () => {
  it("shows a named volume with 'persistent' tag", async () => {
    inspect.mockResolvedValue(
      makeDetail({
        volumes: [{ name: "cache", guest_path: "/data", size_bytes: 1073741824 }],
      }),
    );
    render(<VolumesTab sandbox={running} onChanged={noop} />);
    // The tag badge contains exactly the word "persistent"
    await screen.findByText("persistent");
    expect(screen.getByText(/\/data/)).toBeInTheDocument();
  });

  it("shows a null-name volume with 'ephemeral' tag", async () => {
    inspect.mockResolvedValue(
      makeDetail({
        volumes: [{ name: null, guest_path: "/scratch", size_bytes: 536870912 }],
      }),
    );
    render(<VolumesTab sandbox={running} onChanged={noop} />);
    await screen.findByText("ephemeral");
    expect(screen.getByText(/\/scratch/)).toBeInTheDocument();
  });
});

describe("VolumesTab — dirty banner", () => {
  it("shows 'applied on next restart' banner when a row is added", async () => {
    render(<VolumesTab sandbox={running} onChanged={noop} />);
    // Wait for inspect to resolve and component to render
    await waitFor(() => expect(inspect).toHaveBeenCalled());

    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    expect(await screen.findByText(/applied on next restart/i)).toBeInTheDocument();
  });

  it("does not show the banner before any edit", async () => {
    render(<VolumesTab sandbox={running} onChanged={noop} />);
    await waitFor(() => expect(inspect).toHaveBeenCalled());
    expect(screen.queryByText(/applied on next restart/i)).not.toBeInTheDocument();
  });
});

describe("VolumesTab — Save: attach a new volume", () => {
  it("calls volumeAttach with correct spec string when a new row is saved", async () => {
    render(<VolumesTab sandbox={running} onChanged={noop} />);
    await waitFor(() => expect(inspect).toHaveBeenCalled());

    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));

    // Switch to new persistent type
    fireEvent.click(screen.getByRole("button", { name: /new persistent/i }));

    const nameInput = screen.getByLabelText(/volume 1 name/i);
    const pathInput = screen.getByLabelText(/volume 1 path/i);
    const sizeInput = screen.getByLabelText(/volume 1 size/i);
    fireEvent.change(nameInput, { target: { value: "cache" } });
    fireEvent.change(pathInput, { target: { value: "/data" } });
    fireEvent.change(sizeInput, { target: { value: "1g" } });

    fireEvent.click(screen.getByRole("button", { name: /^save changes$/i }));

    await waitFor(() =>
      expect(volumeAttach).toHaveBeenCalledWith("mysbx", "cache:/data:1g"),
    );
  });
});

describe("VolumesTab — Save: detach a removed seeded volume", () => {
  it("calls volumeDetach with the guest path when a seeded row is removed", async () => {
    inspect.mockResolvedValue(
      makeDetail({
        volumes: [{ name: "cache", guest_path: "/data", size_bytes: 1073741824 }],
      }),
    );
    render(<VolumesTab sandbox={running} onChanged={noop} />);
    await screen.findByText(/\/data/);

    // Remove the seeded row
    fireEvent.click(screen.getByRole("button", { name: /detach.*\/data/i }));

    // Banner should appear
    expect(screen.getByText(/applied on next restart/i)).toBeInTheDocument();

    // Save
    fireEvent.click(screen.getByRole("button", { name: /^save changes$/i }));

    await waitFor(() =>
      expect(volumeDetach).toHaveBeenCalledWith("mysbx", "/data"),
    );
  });
});

describe("VolumesTab — Restart now", () => {
  it("shows Restart now when running and dirty", async () => {
    render(<VolumesTab sandbox={running} onChanged={noop} />);
    await waitFor(() => expect(inspect).toHaveBeenCalled());

    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));

    expect(await screen.findByRole("button", { name: /save & restart now/i })).toBeInTheDocument();
  });

  it("does not show Restart now when stopped even if dirty", async () => {
    render(<VolumesTab sandbox={stopped} onChanged={noop} />);
    await waitFor(() => expect(inspect).toHaveBeenCalled());

    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));

    await screen.findByText(/applied on next restart/i);
    expect(screen.queryByRole("button", { name: /save & restart now/i })).not.toBeInTheDocument();
  });

  it("calls api.restart and onChanged when Restart now is clicked (no pending edits)", async () => {
    const onChanged = vi.fn();
    render(<VolumesTab sandbox={running} onChanged={onChanged} />);
    await waitFor(() => expect(inspect).toHaveBeenCalled());

    // Click "Add volume" to make the component dirty (shows Restart now button)
    // but leave all fields blank so save() treats the row as a no-op and returns true
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    const restartBtn = await screen.findByRole("button", { name: /save & restart now/i });
    fireEvent.click(restartBtn);

    await waitFor(() => expect(restart).toHaveBeenCalledWith("mysbx"));
    await waitFor(() => expect(onChanged).toHaveBeenCalled());
  });

  it("Restart now saves pending edits (calls volumeAttach) before calling restart", async () => {
    const onChanged = vi.fn();
    const callOrder: string[] = [];
    volumeAttach.mockImplementation(async () => { callOrder.push("attach"); });
    restart.mockImplementation(async () => { callOrder.push("restart"); });

    render(<VolumesTab sandbox={running} onChanged={onChanged} />);
    await waitFor(() => expect(inspect).toHaveBeenCalled());

    // Add a new valid volume row
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    fireEvent.click(screen.getByRole("button", { name: /new persistent/i }));
    fireEvent.change(screen.getByLabelText(/volume 1 name/i), { target: { value: "data" } });
    fireEvent.change(screen.getByLabelText(/volume 1 path/i), { target: { value: "/data" } });
    fireEvent.change(screen.getByLabelText(/volume 1 size/i), { target: { value: "2g" } });

    const restartBtn = await screen.findByRole("button", { name: /save & restart now/i });
    fireEvent.click(restartBtn);

    await waitFor(() => expect(restart).toHaveBeenCalledWith("mysbx"));
    expect(callOrder).toEqual(["attach", "restart"]);
    await waitFor(() => expect(onChanged).toHaveBeenCalled());
  });

  it("Restart now does NOT call restart if save fails (validation error)", async () => {
    render(<VolumesTab sandbox={running} onChanged={vi.fn()} />);
    await waitFor(() => expect(inspect).toHaveBeenCalled());

    // Add a row with invalid data so validation fails
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    fireEvent.click(screen.getByRole("button", { name: /new persistent/i }));
    fireEvent.change(screen.getByLabelText(/volume 1 name/i), { target: { value: "data" } });
    fireEvent.change(screen.getByLabelText(/volume 1 path/i), { target: { value: "/data" } });
    // leave size blank — should fail validation

    const restartBtn = await screen.findByRole("button", { name: /save & restart now/i });
    fireEvent.click(restartBtn);

    // restart should NOT be called because save() returned false
    await new Promise((r) => setTimeout(r, 50));
    expect(restart).not.toHaveBeenCalled();
  });
});

describe("VolumesTab — save re-syncs on partial failure", () => {
  it("calls inspect (load) even when volumeAttach rejects and surfaces the error (load also fails)", async () => {
    // Make volumeAttach fail AND keep inspect failing so the error isn't cleared by load()
    const attachError = new Error("disk full");
    volumeAttach.mockRejectedValue(attachError);
    // After the first call (initial load), subsequent inspect calls also fail so the error stays
    inspect
      .mockResolvedValueOnce(makeDetail()) // first call (initial load) succeeds
      .mockRejectedValue(new Error("inspect error")); // subsequent calls fail

    render(<VolumesTab sandbox={running} onChanged={noop} />);
    await waitFor(() => expect(inspect).toHaveBeenCalledTimes(1));

    // Add a new valid volume row
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    fireEvent.click(screen.getByRole("button", { name: /new persistent/i }));
    fireEvent.change(screen.getByLabelText(/volume 1 name/i), { target: { value: "cache" } });
    fireEvent.change(screen.getByLabelText(/volume 1 path/i), { target: { value: "/cache" } });
    fireEvent.change(screen.getByLabelText(/volume 1 size/i), { target: { value: "1g" } });

    fireEvent.click(screen.getByRole("button", { name: /^save changes$/i }));

    // inspect must be called again (the finally-block re-sync load)
    await waitFor(() => expect(inspect).toHaveBeenCalledTimes(2));
    // An error message must be surfaced (either from attach or from the failing load)
    await screen.findByText(/disk full|inspect error/i);
  });

  it("calls inspect (load) even when volumeAttach rejects (inspect succeeds, verifies finally ran)", async () => {
    const attachError = new Error("disk full");
    volumeAttach.mockRejectedValue(attachError);
    // inspect always succeeds (load clears error — proving finally ran, UI re-synced)

    render(<VolumesTab sandbox={running} onChanged={noop} />);
    await waitFor(() => expect(inspect).toHaveBeenCalledTimes(1));

    // Add a new valid volume row
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    fireEvent.click(screen.getByRole("button", { name: /new persistent/i }));
    fireEvent.change(screen.getByLabelText(/volume 1 name/i), { target: { value: "cache" } });
    fireEvent.change(screen.getByLabelText(/volume 1 path/i), { target: { value: "/cache" } });
    fireEvent.change(screen.getByLabelText(/volume 1 size/i), { target: { value: "1g" } });

    fireEvent.click(screen.getByRole("button", { name: /^save changes$/i }));

    // inspect must be called a second time — this proves the finally block ran load()
    await waitFor(() => expect(inspect).toHaveBeenCalledTimes(2));
  });

  it("save error remains visible after finally re-sync when volumeAttach rejects (inspect succeeds)", async () => {
    // inspect always succeeds — this is the scenario where the bug manifests:
    // load() called in finally clears the error that save() just set.
    const attachError = new Error("disk full");
    volumeAttach.mockRejectedValue(attachError);

    render(<VolumesTab sandbox={running} onChanged={noop} />);
    await waitFor(() => expect(inspect).toHaveBeenCalledTimes(1));

    // Add a new valid volume row
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    fireEvent.click(screen.getByRole("button", { name: /new persistent/i }));
    fireEvent.change(screen.getByLabelText(/volume 1 name/i), { target: { value: "cache" } });
    fireEvent.change(screen.getByLabelText(/volume 1 path/i), { target: { value: "/cache" } });
    fireEvent.change(screen.getByLabelText(/volume 1 size/i), { target: { value: "1g" } });

    fireEvent.click(screen.getByRole("button", { name: /^save changes$/i }));

    // (a) inspect must be called again — rows re-synced from daemon
    await waitFor(() => expect(inspect).toHaveBeenCalledTimes(2));
    // (b) the save error must still be visible — NOT cleared by the re-sync load
    expect(screen.getByText(/disk full/i)).toBeInTheDocument();
  });
});

describe("VolumesTab — 3-way volume type selector", () => {
  it("ephemeral type: emits path:size spec on Save", async () => {
    render(<VolumesTab sandbox={running} onChanged={noop} />);
    await waitFor(() => expect(inspect).toHaveBeenCalled());

    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));

    // Choose Ephemeral (should be default, or click the button)
    const ephBtn = screen.getByRole("button", { name: /ephemeral/i });
    fireEvent.click(ephBtn);

    fireEvent.change(screen.getByLabelText(/volume 1 path/i), { target: { value: "/scratch" } });
    fireEvent.change(screen.getByLabelText(/volume 1 size/i), { target: { value: "1g" } });

    fireEvent.click(screen.getByRole("button", { name: /^save changes$/i }));
    await waitFor(() =>
      expect(volumeAttach).toHaveBeenCalledWith("mysbx", "/scratch:1g"),
    );
  });

  it("new persistent type: emits name:path:size spec on Save", async () => {
    render(<VolumesTab sandbox={running} onChanged={noop} />);
    await waitFor(() => expect(inspect).toHaveBeenCalled());

    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));

    const newPersBtn = screen.getByRole("button", { name: /new persistent/i });
    fireEvent.click(newPersBtn);

    fireEvent.change(screen.getByLabelText(/volume 1 name/i), { target: { value: "cache" } });
    fireEvent.change(screen.getByLabelText(/volume 1 path/i), { target: { value: "/data" } });
    fireEvent.change(screen.getByLabelText(/volume 1 size/i), { target: { value: "2g" } });

    fireEvent.click(screen.getByRole("button", { name: /^save changes$/i }));
    await waitFor(() =>
      expect(volumeAttach).toHaveBeenCalledWith("mysbx", "cache:/data:2g"),
    );
  });

  it("existing persistent type: emits name:path:sizeMiB m spec on Save", async () => {
    volumeList.mockResolvedValue([
      { name: "archive", size_bytes: 1073741824, actual_bytes: 0, referenced_by: [] },
    ]);
    render(<VolumesTab sandbox={running} onChanged={noop} />);
    await waitFor(() => expect(inspect).toHaveBeenCalled());

    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));

    const existingBtn = screen.getByRole("button", { name: /existing/i });
    fireEvent.click(existingBtn);

    // Select from dropdown
    const select = screen.getByRole("combobox", { name: /existing volume/i });
    fireEvent.change(select, { target: { value: "archive" } });

    fireEvent.change(screen.getByLabelText(/volume 1 path/i), { target: { value: "/arch" } });

    fireEvent.click(screen.getByRole("button", { name: /^save changes$/i }));
    await waitFor(() =>
      expect(volumeAttach).toHaveBeenCalledWith("mysbx", "archive:/arch:1024m"),
    );
  });

  it("existing persistent dropdown excludes in-use volumes (referenced_by non-empty)", async () => {
    volumeList.mockResolvedValue([
      { name: "archive", size_bytes: 1073741824, actual_bytes: 0, referenced_by: [] },
      { name: "inuse", size_bytes: 1073741824, actual_bytes: 0, referenced_by: ["other-sbx"] },
    ]);
    render(<VolumesTab sandbox={running} onChanged={noop} />);
    await waitFor(() => expect(inspect).toHaveBeenCalled());

    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    fireEvent.click(screen.getByRole("button", { name: /existing/i }));

    await waitFor(() => expect(volumeList).toHaveBeenCalled());
    const select = screen.getByRole("combobox", { name: /existing volume/i });
    // "archive" option should be present, "inuse" should not
    expect(select).toBeInTheDocument();
    const opts = select.querySelectorAll('option');
    const optTexts = Array.from(opts).map(o => o.textContent);
    expect(optTexts.some(t => t?.includes("archive"))).toBe(true);
    expect(optTexts.some(t => t?.includes("inuse"))).toBe(false);
  });

  it("existing persistent dropdown excludes volumes already seeded on this sandbox", async () => {
    volumeList.mockResolvedValue([
      { name: "cache", size_bytes: 1073741824, actual_bytes: 0, referenced_by: [] },
      { name: "archive", size_bytes: 1073741824, actual_bytes: 0, referenced_by: [] },
    ]);
    inspect.mockResolvedValue(makeDetail({
      volumes: [{ name: "cache", guest_path: "/data", size_bytes: 1073741824 }],
    }));
    render(<VolumesTab sandbox={running} onChanged={noop} />);
    await screen.findByText(/\/data/);

    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    fireEvent.click(screen.getByRole("button", { name: /existing/i }));

    await waitFor(() => expect(volumeList).toHaveBeenCalled());
    const select = screen.getByRole("combobox", { name: /existing volume/i });
    const opts = select.querySelectorAll('option');
    const optTexts = Array.from(opts).map(o => o.textContent);
    // "cache" is already seeded, should not appear
    expect(optTexts.some(t => t?.includes("archive"))).toBe(true);
    expect(optTexts.some(t => t?.includes("cache"))).toBe(false);
  });
});

describe("VolumesTab — persistent caveat tooltip", () => {
  it("persistent tag has single-writer tooltip, not a visible paragraph", async () => {
    inspect.mockResolvedValue(makeDetail({
      volumes: [
        { name: "cache", guest_path: "/data", size_bytes: 1073741824 },
        { name: "other", guest_path: "/other", size_bytes: 1073741824 },
      ],
    }));
    render(<VolumesTab sandbox={running} onChanged={noop} />);
    await screen.findAllByText("persistent");
    // The caveat text must NOT be a visible paragraph (not in the document)
    expect(screen.queryByText(/single-writer/i)).not.toBeInTheDocument();
    // The badge must carry the tooltip
    const badges = screen.getAllByText("persistent");
    expect(badges[0]).toHaveAttribute("title", expect.stringMatching(/single-writer/i));
  });
});
