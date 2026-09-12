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

const stopped: SandboxView = {
  name: "management",
  image: "docker/sandbox-templates:claude-code",
  state: { kind: "stopped" },
};

const detail: SandboxDetail = {
  name: "management",
  image: "docker/sandbox-templates:claude-code",
  status: "stopped",
  workspace: "/ws",
  ports: [],
  volumes: [],
  container: null,
  docker: false,
  cpus: 2,
  mem_mb: 4096,
  confinement: null,
  vnc: false,
  vnc_running: false,
  vnc_url: null,
  vnc_restart_required: false,
};

/** Add one "New persistent" row and fill it the way a user would. */
async function fillNewPersistentRow(size: string) {
  render(<VolumesTab sandbox={stopped} onChanged={() => {}} />);
  await waitFor(() => expect(inspect).toHaveBeenCalled());
  fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
  fireEvent.click(screen.getByRole("radio", { name: /new persistent/i }));
  fireEvent.change(screen.getByLabelText(/volume 1 name/i), {
    target: { value: "management-persistent" },
  });
  fireEvent.change(screen.getByLabelText(/volume 1 path/i), { target: { value: "/data" } });
  fireEvent.change(screen.getByLabelText(/volume 1 size/i), { target: { value: size } });
}

beforeEach(() => {
  vi.clearAllMocks();
  inspect.mockResolvedValue(detail);
  volumeAttach.mockResolvedValue(undefined);
  volumeDetach.mockResolvedValue(undefined);
  restart.mockResolvedValue(undefined);
  volumeList.mockResolvedValue([]);
});

// ── tests ─────────────────────────────────────────────────────────────────────

/**
 * #292: a 5 GiB persistent volume typed as "5GB" (the spelling every disk
 * tool uses) left Save greyed out with no explanation the user connected to
 * the field. The size input must take the common spellings and the daemon
 * must receive the canonical `<n>g` form.
 */
describe("VolumesTab — size input spellings (#292)", () => {
  it("'5GB' is accepted and attached as 'management-persistent:/data:5g'", async () => {
    await fillNewPersistentRow("5GB");

    const save = screen.getByRole("button", { name: /^save changes$/i });
    expect(save).toBeEnabled();
    expect(screen.queryByText(/size must be/i)).not.toBeInTheDocument();

    fireEvent.click(save);
    await waitFor(() =>
      expect(volumeAttach).toHaveBeenCalledWith("management", "management-persistent:/data:5g"),
    );
  });

  it("a size it cannot parse keeps Save disabled AND says why next to the button", async () => {
    await fillNewPersistentRow("5KB");

    expect(screen.getByRole("button", { name: /^save changes$/i })).toBeDisabled();
    // The reason sits in the banner, next to the disabled button — not only
    // as a small line under the field the user may have scrolled past.
    expect(screen.getByText(/fix the invalid volume row/i)).toBeInTheDocument();
  });

  it("no restart button is offered for a stopped sandbox", async () => {
    await fillNewPersistentRow("5g");
    expect(screen.queryByRole("button", { name: /restart now/i })).not.toBeInTheDocument();
  });

  it("the Save button reads 'Saving…' while the attach is in flight", async () => {
    let release: () => void = () => {};
    volumeAttach.mockImplementation(
      () =>
        new Promise<void>((resolve) => {
          release = resolve;
        }),
    );
    await fillNewPersistentRow("5g");
    fireEvent.click(screen.getByRole("button", { name: /^save changes$/i }));

    const saving = await screen.findByRole("button", { name: /^saving…$/i });
    expect(saving).toBeDisabled();
    release();
    // Once the attach lands the rows re-sync to daemon truth, the tab is no
    // longer dirty, and the banner (with its button) goes away.
    await waitFor(() =>
      expect(screen.queryByRole("button", { name: /^saving…$/i })).not.toBeInTheDocument(),
    );
    expect(volumeAttach).toHaveBeenCalledWith("management", "management-persistent:/data:5g");
  });
});
