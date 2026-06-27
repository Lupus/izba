import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach } from "vitest";
import type { SandboxView, SandboxDetail, VolumeInfo } from "../lib/types";
import { freeVolumes, usedExistingNames } from "../lib/volumevalidate";

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

  it("empty new-row hint does not claim 'No volumes' when a volume is attached", async () => {
    inspect.mockResolvedValue(
      makeDetail({
        volumes: [{ name: "scratch2", guest_path: "/scratch2", size_bytes: 1073741824 }],
      }),
    );
    render(<VolumesTab sandbox={running} onChanged={noop} />);
    await screen.findByText(/\/scratch2/);
    // The attached volume is listed above; the empty new-row hint must not
    // contradict it by saying "No volumes".
    expect(screen.queryByText(/no volumes/i)).not.toBeInTheDocument();
    expect(screen.getByText(/add a volume to mount another path/i)).toBeInTheDocument();
  });
});

describe("VolumesTab — dirty banner", () => {
  it("shows 'applied on next restart' banner when a valid inline row is added", async () => {
    render(<VolumesTab sandbox={running} onChanged={noop} />);
    await waitFor(() => expect(inspect).toHaveBeenCalled());

    // Click Add volume, then fill inline fields
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    fireEvent.change(screen.getByLabelText(/volume 1 path/i), { target: { value: "/data" } });
    fireEvent.change(screen.getByLabelText(/volume 1 size/i), { target: { value: "1g" } });

    expect(await screen.findByText(/applied on next restart/i)).toBeInTheDocument();
  });

  it("does not show the banner before any edit", async () => {
    render(<VolumesTab sandbox={running} onChanged={noop} />);
    await waitFor(() => expect(inspect).toHaveBeenCalled());
    expect(screen.queryByText(/applied on next restart/i)).not.toBeInTheDocument();
  });

  it("banner gone after add-then-remove inline volume row", async () => {
    render(<VolumesTab sandbox={running} onChanged={noop} />);
    await waitFor(() => expect(inspect).toHaveBeenCalled());

    // Add a valid inline row
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    fireEvent.change(screen.getByLabelText(/volume 1 path/i), { target: { value: "/data" } });
    fireEvent.change(screen.getByLabelText(/volume 1 size/i), { target: { value: "1g" } });
    await screen.findByText(/applied on next restart/i);

    // Remove the inline row with ×
    fireEvent.click(screen.getByRole("button", { name: /remove volume 1/i }));
    expect(screen.queryByText(/applied on next restart/i)).not.toBeInTheDocument();
  });

  it("fully blank new row does NOT trigger banner", async () => {
    render(<VolumesTab sandbox={running} onChanged={noop} />);
    await waitFor(() => expect(inspect).toHaveBeenCalled());

    // Add row but leave all fields blank
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    expect(screen.queryByText(/applied on next restart/i)).not.toBeInTheDocument();
  });
});

describe("VolumesTab — inline row validation (live errors)", () => {
  it("typing invalid path in inline row shows error live (no Add click needed)", async () => {
    render(<VolumesTab sandbox={running} onChanged={noop} />);
    await waitFor(() => expect(inspect).toHaveBeenCalled());

    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    fireEvent.change(screen.getByLabelText(/volume 1 path/i), { target: { value: "nopath" } });

    expect(screen.getByText(/guest path must be absolute/i)).toBeInTheDocument();
  });

  it("non-blank invalid row blocks Save (disables button)", async () => {
    // Use a seeded volume so we can detach it to make the banner appear
    inspect.mockResolvedValue(
      makeDetail({
        volumes: [{ name: "cache", guest_path: "/data", size_bytes: 1073741824 }],
      }),
    );
    render(<VolumesTab sandbox={running} onChanged={noop} />);
    await screen.findByText(/\/data/);

    // Detach seeded row to make dirty (banner appears)
    fireEvent.click(screen.getByRole("button", { name: /detach.*\/data/i }));
    expect(screen.getByText(/applied on next restart/i)).toBeInTheDocument();

    // Now add an invalid inline row
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    fireEvent.change(screen.getByLabelText(/volume 1 path/i), { target: { value: "x" } });

    // Save button should be disabled because volumesInvalid
    expect(screen.getByRole("button", { name: /^save changes$/i })).toBeDisabled();
  });

  it("error messages not shown before field is touched (blank path → no error)", async () => {
    render(<VolumesTab sandbox={running} onChanged={noop} />);
    await waitFor(() => expect(inspect).toHaveBeenCalled());

    // Add row but don't type anything
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    expect(screen.queryByText(/must be a number/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/must be absolute/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/name must match/i)).not.toBeInTheDocument();
  });

  it("shows path error when path lacks leading slash", async () => {
    render(<VolumesTab sandbox={running} onChanged={noop} />);
    await waitFor(() => expect(inspect).toHaveBeenCalled());

    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    fireEvent.change(screen.getByLabelText(/volume 1 path/i), { target: { value: "data" } });
    fireEvent.change(screen.getByLabelText(/volume 1 size/i), { target: { value: "1g" } });

    expect(screen.getByText(/guest path must be absolute/i)).toBeInTheDocument();
  });

  it("shows name error when new_persistent name is invalid (after typing)", async () => {
    render(<VolumesTab sandbox={running} onChanged={noop} />);
    await waitFor(() => expect(inspect).toHaveBeenCalled());

    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    fireEvent.click(screen.getByRole("radio", { name: /new persistent/i }));
    // Type an invalid name (uppercase not allowed)
    fireEvent.change(screen.getByLabelText(/volume 1 name/i), { target: { value: "Bad-Name" } });

    expect(screen.getByText(/name must match/i)).toBeInTheDocument();
  });

  it("shows pick error when existing_persistent has path but no volume selected", async () => {
    render(<VolumesTab sandbox={running} onChanged={noop} />);
    await waitFor(() => expect(inspect).toHaveBeenCalled());

    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    fireEvent.click(screen.getByRole("radio", { name: /existing/i }));
    fireEvent.change(screen.getByLabelText(/volume 1 path/i), { target: { value: "/arch" } });

    expect(screen.getByText(/select a volume/i)).toBeInTheDocument();
  });
});

describe("VolumesTab — Save: attach a new volume", () => {
  it("calls volumeAttach with correct spec string when a new row is saved", async () => {
    render(<VolumesTab sandbox={running} onChanged={noop} />);
    await waitFor(() => expect(inspect).toHaveBeenCalled());

    // Click Add volume, switch to new persistent, fill fields
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    fireEvent.click(screen.getByRole("radio", { name: /new persistent/i }));

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

describe("VolumesTab — Detach vs Remove label by kind", () => {
  it("seeded persistent shows 'Detach' button", async () => {
    inspect.mockResolvedValue(
      makeDetail({
        volumes: [{ name: "cache", guest_path: "/data", size_bytes: 1073741824 }],
      }),
    );
    render(<VolumesTab sandbox={running} onChanged={noop} />);
    await screen.findByText(/\/data/);
    expect(screen.getByRole("button", { name: /^detach \/data$/i })).toBeInTheDocument();
  });

  it("seeded ephemeral shows 'Remove' button", async () => {
    inspect.mockResolvedValue(
      makeDetail({
        volumes: [{ name: null, guest_path: "/scratch", size_bytes: 536870912 }],
      }),
    );
    render(<VolumesTab sandbox={running} onChanged={noop} />);
    await screen.findByText(/\/scratch/);
    expect(screen.getByRole("button", { name: /^remove \/scratch$/i })).toBeInTheDocument();
  });

  it("both Detach and Remove trigger volumeDetach on save", async () => {
    inspect.mockResolvedValue(
      makeDetail({
        volumes: [
          { name: "cache", guest_path: "/data", size_bytes: 1073741824 },
          { name: null, guest_path: "/scratch", size_bytes: 536870912 },
        ],
      }),
    );
    render(<VolumesTab sandbox={running} onChanged={noop} />);
    await screen.findByText(/\/data/);

    fireEvent.click(screen.getByRole("button", { name: /^detach \/data$/i }));
    fireEvent.click(screen.getByRole("button", { name: /^remove \/scratch$/i }));
    fireEvent.click(screen.getByRole("button", { name: /^save changes$/i }));

    await waitFor(() => expect(volumeDetach).toHaveBeenCalledWith("mysbx", "/data"));
    await waitFor(() => expect(volumeDetach).toHaveBeenCalledWith("mysbx", "/scratch"));
  });
});

describe("VolumesTab — Restart now", () => {
  it("shows Restart now when running and dirty", async () => {
    render(<VolumesTab sandbox={running} onChanged={noop} />);
    await waitFor(() => expect(inspect).toHaveBeenCalled());

    // Add a valid inline row to make dirty
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    fireEvent.change(screen.getByLabelText(/volume 1 path/i), { target: { value: "/data" } });
    fireEvent.change(screen.getByLabelText(/volume 1 size/i), { target: { value: "1g" } });

    expect(await screen.findByRole("button", { name: /save & restart now/i })).toBeInTheDocument();
  });

  it("does not show Restart now when stopped even if dirty", async () => {
    render(<VolumesTab sandbox={stopped} onChanged={noop} />);
    await waitFor(() => expect(inspect).toHaveBeenCalled());

    // Add a valid inline row to make dirty
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    fireEvent.change(screen.getByLabelText(/volume 1 path/i), { target: { value: "/data" } });
    fireEvent.change(screen.getByLabelText(/volume 1 size/i), { target: { value: "1g" } });

    await screen.findByText(/applied on next restart/i);
    expect(screen.queryByRole("button", { name: /save & restart now/i })).not.toBeInTheDocument();
  });

  it("calls api.restart and onChanged when Restart now is clicked (with valid inline row)", async () => {
    const onChanged = vi.fn();
    render(<VolumesTab sandbox={running} onChanged={onChanged} />);
    await waitFor(() => expect(inspect).toHaveBeenCalled());

    // Add a valid inline row
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    fireEvent.change(screen.getByLabelText(/volume 1 path/i), { target: { value: "/data" } });
    fireEvent.change(screen.getByLabelText(/volume 1 size/i), { target: { value: "1g" } });

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

    // Add a new valid inline row
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    fireEvent.click(screen.getByRole("radio", { name: /new persistent/i }));
    fireEvent.change(screen.getByLabelText(/volume 1 name/i), { target: { value: "data" } });
    fireEvent.change(screen.getByLabelText(/volume 1 path/i), { target: { value: "/data" } });
    fireEvent.change(screen.getByLabelText(/volume 1 size/i), { target: { value: "2g" } });

    const restartBtn = await screen.findByRole("button", { name: /save & restart now/i });
    fireEvent.click(restartBtn);

    await waitFor(() => expect(restart).toHaveBeenCalledWith("mysbx"));
    expect(callOrder).toEqual(["attach", "restart"]);
    await waitFor(() => expect(onChanged).toHaveBeenCalled());
  });

  it("Restart now does NOT call restart if save fails (API error)", async () => {
    volumeAttach.mockRejectedValue(new Error("disk full"));
    render(<VolumesTab sandbox={running} onChanged={vi.fn()} />);
    await waitFor(() => expect(inspect).toHaveBeenCalled());

    // Add a valid inline row
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    fireEvent.change(screen.getByLabelText(/volume 1 path/i), { target: { value: "/data" } });
    fireEvent.change(screen.getByLabelText(/volume 1 size/i), { target: { value: "2g" } });

    const restartBtn = await screen.findByRole("button", { name: /save & restart now/i });
    fireEvent.click(restartBtn);

    // restart should NOT be called because save() failed (volumeAttach threw)
    await waitFor(() => expect(volumeAttach).toHaveBeenCalled());
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

    // Add a new valid inline row
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    fireEvent.click(screen.getByRole("radio", { name: /new persistent/i }));
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

    // Add a new valid inline row
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    fireEvent.click(screen.getByRole("radio", { name: /new persistent/i }));
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

    // Add a new valid inline row
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    fireEvent.click(screen.getByRole("radio", { name: /new persistent/i }));
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
    // Choose Ephemeral (should be default, or click the radio)
    const ephBtn = screen.getByRole("radio", { name: /ephemeral/i });
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
    const newPersBtn = screen.getByRole("radio", { name: /new persistent/i });
    fireEvent.click(newPersBtn);

    fireEvent.change(screen.getByLabelText(/volume 1 name/i), { target: { value: "cache" } });
    fireEvent.change(screen.getByLabelText(/volume 1 path/i), { target: { value: "/data" } });
    fireEvent.change(screen.getByLabelText(/volume 1 size/i), { target: { value: "2g" } });

    fireEvent.click(screen.getByRole("button", { name: /^save changes$/i }));
    await waitFor(() =>
      expect(volumeAttach).toHaveBeenCalledWith("mysbx", "cache:/data:2g"),
    );
  });

  it("existing persistent type: select trigger is present with accessible name", async () => {
    volumeList.mockResolvedValue([
      { name: "archive", size_bytes: 1073741824, actual_bytes: 0, referenced_by: [] },
    ]);
    render(<VolumesTab sandbox={running} onChanged={noop} />);
    await waitFor(() => expect(inspect).toHaveBeenCalled());

    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    fireEvent.click(screen.getByRole("radio", { name: /existing/i }));

    await waitFor(() => expect(volumeList).toHaveBeenCalled());
    // Radix Select trigger is present with the accessible name
    expect(screen.getByRole("combobox", { name: /existing volume/i })).toBeInTheDocument();
    // Note: open+pick is exercised in the browser test (volumeRowEditor.browser.test.tsx)
  });

  // The existing-volume options live in a closed Radix portal that jsdom doesn't
  // mount, so the dropdown CONTENTS can't be asserted in jsdom (the open+pick path
  // is covered in volumeRowEditor.browser.test.tsx). What VolumesTab is responsible
  // for is the FILTERING that produces each row's `freeVolumes` prop. That filter is
  // the pure `freeVolumes(allVolumes, seededNames, usedNames)` the component calls
  // (see VolumesTab.freeVolumesFor); these tests assert that contract on the exact
  // scenarios the integration cases used, so they FAIL if the filter regresses.
  it("existing persistent dropdown excludes in-use volumes (referenced_by non-empty)", async () => {
    volumeList.mockResolvedValue([
      { name: "archive", size_bytes: 1073741824, actual_bytes: 0, referenced_by: [] },
      { name: "inuse", size_bytes: 1073741824, actual_bytes: 0, referenced_by: ["other-sbx"] },
    ]);
    render(<VolumesTab sandbox={running} onChanged={noop} />);
    await waitFor(() => expect(inspect).toHaveBeenCalled());

    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    fireEvent.click(screen.getByRole("radio", { name: /existing/i }));
    await waitFor(() => expect(volumeList).toHaveBeenCalled());
    expect(screen.getByRole("combobox", { name: /existing volume/i })).toBeInTheDocument();

    // Filtering contract: a referenced volume is excluded, a free one is kept.
    const allVolumes: VolumeInfo[] = await volumeList.mock.results[0].value;
    const free = freeVolumes(allVolumes, new Set(), usedExistingNames([], 0)).map((v) => v.name);
    expect(free).toContain("archive");
    expect(free).not.toContain("inuse");
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
    fireEvent.click(screen.getByRole("radio", { name: /existing/i }));
    await waitFor(() => expect(volumeList).toHaveBeenCalled());
    expect(screen.getByRole("combobox", { name: /existing volume/i })).toBeInTheDocument();

    // Filtering contract: a volume already seeded on this sandbox ("cache") is excluded.
    const allVolumes: VolumeInfo[] = await volumeList.mock.results[0].value;
    const seededNames = new Set(["cache"]);
    const free = freeVolumes(allVolumes, seededNames, new Set()).map((v) => v.name);
    expect(free).toContain("archive");
    expect(free).not.toContain("cache");
  });

  it("existing persistent dropdown excludes volumes already in another inline row", async () => {
    volumeList.mockResolvedValue([
      { name: "vol1", size_bytes: 1073741824, actual_bytes: 0, referenced_by: [] },
      { name: "vol2", size_bytes: 1073741824, actual_bytes: 0, referenced_by: [] },
    ]);
    render(<VolumesTab sandbox={running} onChanged={noop} />);
    await waitFor(() => expect(inspect).toHaveBeenCalled());

    // Two existing-persistent rows, the first having picked "vol1".
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    fireEvent.click(screen.getByRole("radio", { name: /existing/i }));
    await waitFor(() => expect(volumeList).toHaveBeenCalled());
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    fireEvent.click(screen.getAllByRole("radio", { name: /existing/i })[1]);
    expect(screen.getAllByRole("combobox", { name: /existing volume/i })).toHaveLength(2);

    // Filtering contract: vol1 (picked by row 0) is excluded from row 1's free list.
    const allVolumes: VolumeInfo[] = await volumeList.mock.results[0].value;
    const rows = [
      { kind: "existing_persistent" as const, name: "", path: "", size: "", selectedVolName: "vol1" },
      { kind: "existing_persistent" as const, name: "", path: "", size: "", selectedVolName: "" },
    ];
    const freeForRow1 = freeVolumes(allVolumes, new Set(), usedExistingNames(rows, 1)).map((v) => v.name);
    expect(freeForRow1).toContain("vol2");
    expect(freeForRow1).not.toContain("vol1");
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
