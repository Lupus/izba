import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach } from "vitest";
import type { VolumeInfo } from "../lib/types";

// ── hoisted mocks ─────────────────────────────────────────────────────────────

const { volumeList, volumeRemove, volumePrune } = vi.hoisted(() => ({
  volumeList: vi.fn(),
  volumeRemove: vi.fn(),
  volumePrune: vi.fn(),
}));

vi.mock("../lib/ipc", () => ({
  api: { volumeList, volumeRemove, volumePrune },
}));

import { StorageView } from "../components/StorageView";

// ── helpers ───────────────────────────────────────────────────────────────────

function makeVolume(overrides: Partial<VolumeInfo> = {}): VolumeInfo {
  return {
    name: "data",
    size_bytes: 1073741824,
    actual_bytes: 536870912,
    referenced_by: [],
    ...overrides,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  volumeList.mockResolvedValue([]);
  volumeRemove.mockResolvedValue(undefined);
  volumePrune.mockResolvedValue({ removed: [], reclaimed_bytes: 0 });
});

// ── tests ─────────────────────────────────────────────────────────────────────

describe("StorageView — renders volumes", () => {
  it("renders volume names from volumeList", async () => {
    volumeList.mockResolvedValue([
      makeVolume({ name: "cache" }),
      makeVolume({ name: "data" }),
    ]);
    render(<StorageView />);
    await screen.findByText("cache");
    expect(screen.getByText("data")).toBeInTheDocument();
  });

  it("formats size_bytes human-readable (Used column is not displayed)", async () => {
    volumeList.mockResolvedValue([
      makeVolume({ name: "cache", size_bytes: 1073741824, actual_bytes: 536870912 }),
    ]);
    render(<StorageView />);
    await screen.findByText("cache");
    // 1073741824 = 1.0 GiB — Size column is present
    expect(screen.getByText(/1\.0 GiB|1\.00 GiB|1 GiB/)).toBeInTheDocument();
    // actual_bytes (512 MiB) is NOT rendered — the Used column was removed
    expect(screen.queryByText(/512 MiB|512\.0 MiB|0\.5 GiB/)).not.toBeInTheDocument();
    // No "Used" column header
    expect(screen.queryByRole("columnheader", { name: /^used$/i })).not.toBeInTheDocument();
  });

  it("shows a hint explaining how to create persistent volumes", async () => {
    volumeList.mockResolvedValue([]);
    render(<StorageView />);
    await waitFor(() => expect(volumeList).toHaveBeenCalled());
    expect(
      screen.getByText(/persistent volumes are created when you attach/i),
    ).toBeInTheDocument();
  });

  it("shows in-use chips when referenced_by is non-empty", async () => {
    volumeList.mockResolvedValue([
      makeVolume({ name: "shared", referenced_by: ["web", "api"] }),
    ]);
    render(<StorageView />);
    await screen.findByText("shared");
    expect(screen.getByText("web")).toBeInTheDocument();
    expect(screen.getByText("api")).toBeInTheDocument();
  });

  it("Delete is disabled with a title when volume is in use", async () => {
    volumeList.mockResolvedValue([
      makeVolume({ name: "shared", referenced_by: ["web", "api"] }),
    ]);
    render(<StorageView />);
    await screen.findByText("shared");
    const deleteBtn = screen.getByRole("button", { name: /^delete$/i });
    expect(deleteBtn).toBeDisabled();
    expect(deleteBtn).toHaveAttribute("title");
    expect(deleteBtn.getAttribute("title")).toMatch(/web|api/);
  });

  it("Delete is enabled when referenced_by is empty", async () => {
    volumeList.mockResolvedValue([
      makeVolume({ name: "unused", referenced_by: [] }),
    ]);
    render(<StorageView />);
    await screen.findByText("unused");
    const deleteBtn = screen.getByRole("button", { name: /^delete$/i });
    expect(deleteBtn).toBeEnabled();
  });
});

describe("StorageView — Delete action", () => {
  it("opens confirm dialog when Delete is clicked on an unreferenced volume", async () => {
    volumeList.mockResolvedValue([
      makeVolume({ name: "mydata", referenced_by: [] }),
    ]);
    render(<StorageView />);
    await screen.findByText("mydata");

    fireEvent.click(screen.getByRole("button", { name: /^delete$/i }));

    // ConfirmDialog should appear
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("calls volumeRemove and reloads after confirm", async () => {
    volumeList.mockResolvedValue([
      makeVolume({ name: "mydata", referenced_by: [] }),
    ]);
    render(<StorageView />);
    await screen.findByText("mydata");

    // Click the row-level Delete button (before dialog opens)
    const rowDelete = screen.getByRole("button", { name: /^delete$/i });
    fireEvent.click(rowDelete);

    // Dialog is now open — confirm button inside the dialog
    const dialog = screen.getByRole("dialog");
    const dialogConfirm = Array.from(dialog.querySelectorAll("button")).find(
      (b) => b.textContent && /delete/i.test(b.textContent),
    );
    fireEvent.click(dialogConfirm!);

    await waitFor(() => expect(volumeRemove).toHaveBeenCalledWith("mydata"));
    // volumeList is called again after remove
    await waitFor(() => expect(volumeList).toHaveBeenCalledTimes(2));
  });

  it("does not call volumeRemove when cancel is clicked", async () => {
    volumeList.mockResolvedValue([
      makeVolume({ name: "mydata", referenced_by: [] }),
    ]);
    render(<StorageView />);
    await screen.findByText("mydata");

    fireEvent.click(screen.getByRole("button", { name: /^delete$/i }));

    fireEvent.click(screen.getByRole("button", { name: /cancel/i }));

    expect(volumeRemove).not.toHaveBeenCalled();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});

describe("StorageView — Prune unused", () => {
  it("opens confirm dialog when Prune unused is clicked", async () => {
    volumeList.mockResolvedValue([]);
    render(<StorageView />);
    await waitFor(() => expect(volumeList).toHaveBeenCalled());

    fireEvent.click(screen.getByRole("button", { name: /prune unused/i }));
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("calls volumePrune and shows reclaimed bytes after confirm", async () => {
    volumeList.mockResolvedValue([]);
    volumePrune.mockResolvedValue({ removed: ["old", "stale"], reclaimed_bytes: 2147483648 });
    render(<StorageView />);
    await waitFor(() => expect(volumeList).toHaveBeenCalled());

    fireEvent.click(screen.getByRole("button", { name: /prune unused/i }));

    // Confirm inside the dialog
    const dialog = screen.getByRole("dialog");
    const confirmBtn = Array.from(dialog.querySelectorAll("button")).find(
      (b) => b.textContent && /prune/i.test(b.textContent),
    );
    fireEvent.click(confirmBtn!);

    await waitFor(() => expect(volumePrune).toHaveBeenCalled());
    // Should show reclaimed bytes — look for the formatted value in the strong element
    await screen.findByText(/2(\.0)? GiB|2147/i);
  });

  it("calls volumeList again after prune to refresh", async () => {
    volumeList.mockResolvedValue([]);
    volumePrune.mockResolvedValue({ removed: [], reclaimed_bytes: 0 });
    render(<StorageView />);
    await waitFor(() => expect(volumeList).toHaveBeenCalledTimes(1));

    fireEvent.click(screen.getByRole("button", { name: /prune unused/i }));
    const dialog = screen.getByRole("dialog");
    const confirmBtn = Array.from(dialog.querySelectorAll("button")).find(
      (b) => b.textContent && /prune/i.test(b.textContent),
    );
    fireEvent.click(confirmBtn!);

    await waitFor(() => expect(volumeList).toHaveBeenCalledTimes(2));
  });
});

/** DEEP-F1 — the rail must not answer "which named volumes exist?" before it
 *  has asked, and must not answer it at all when the answer never came.
 *
 *  Before `volumeList` resolved — and again when it REJECTED, since the empty
 *  state carried no `!error` guard — this view rendered "No named volumes."
 *  while `Prune unused` stayed live. `volume_prune` deletes every named volume
 *  image not referenced by any sandbox, and volume images are NOT recoverable.
 *  The daemon computes the scope, so no UI fiction is written back — but the
 *  operator's consent was taken against a blank screen, and the confirmation
 *  names no volume, so nothing in the flow can correct the impression.
 *
 *  Every assertion below is on the API MOCK, never on a `disabled` attribute:
 *  the guard that matters lives in the prune handler itself. Each refusal test
 *  also asserts the refusal is VISIBLE, which is what stops it passing
 *  vacuously — a natively `disabled` button would swallow the click, render no
 *  reason, and make the assertion meaningless. */
describe("StorageView load state", () => {
  /** A `volumeList` that never settles — the "still loading" window. */
  function pendingVolumeList() {
    volumeList.mockReturnValue(new Promise(() => {}));
  }

  /** Drive the whole operator gesture: click Prune, and — if a confirmation
   *  still appears — follow it through. An unguarded build reaches
   *  `volumePrune` here, which is the irreversible call; a guarded one never
   *  opens the dialog and says why. */
  function pruneAllTheWay() {
    fireEvent.click(screen.getByRole("button", { name: /prune unused/i }));
    const dialog = screen.queryByRole("dialog");
    if (dialog) {
      const confirmBtn = Array.from(dialog.querySelectorAll("button")).find(
        (b) => b.textContent && /prune/i.test(b.textContent),
      );
      if (confirmBtn) fireEvent.click(confirmBtn);
    }
  }

  it("refuses to prune while the volume list is still loading (volumePrune never called)", async () => {
    pendingVolumeList();
    render(<StorageView />);
    pruneAllTheWay();
    expect(volumePrune).not.toHaveBeenCalled();
    await waitFor(() => expect(screen.getByText(/refus/i)).toBeInTheDocument());
    // No confirmation dialog either: it cannot describe a scope izba has not read.
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(volumePrune).not.toHaveBeenCalled();
  });

  it("refuses to prune after the volume list failed to load (volumePrune never called)", async () => {
    volumeList.mockRejectedValue(new Error("daemon unreachable"));
    render(<StorageView />);
    await screen.findByText(/daemon unreachable/i);
    pruneAllTheWay();
    expect(volumePrune).not.toHaveBeenCalled();
    await waitFor(() => expect(screen.getByText(/refus/i)).toBeInTheDocument());
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(volumePrune).not.toHaveBeenCalled();
    // The load failure stays on screen: an errored list is not an empty one.
    expect(screen.getByText(/daemon unreachable/i)).toBeInTheDocument();
  });

  it("claims no emptiness while the volume list is loading", () => {
    pendingVolumeList();
    render(<StorageView />);
    expect(screen.queryByText(/no named volumes/i)).not.toBeInTheDocument();
  });

  it("claims no emptiness after the volume list failed to load", async () => {
    volumeList.mockRejectedValue(new Error("daemon unreachable"));
    render(<StorageView />);
    await screen.findByText(/daemon unreachable/i);
    expect(screen.queryByText(/no named volumes/i)).not.toBeInTheDocument();
  });

  it("still prunes for a genuinely loaded, genuinely empty list", async () => {
    volumeList.mockResolvedValue([]);
    render(<StorageView />);
    await screen.findByText(/no named volumes/i);
    fireEvent.click(screen.getByRole("button", { name: /prune unused/i }));
    const dialog = screen.getByRole("dialog");
    const confirmBtn = Array.from(dialog.querySelectorAll("button")).find(
      (b) => b.textContent && /prune/i.test(b.textContent),
    );
    fireEvent.click(confirmBtn!);
    await waitFor(() => expect(volumePrune).toHaveBeenCalled());
  });
});
