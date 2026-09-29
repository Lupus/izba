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
  name: "management",
  image: "docker/sandbox-templates:claude-code",
  state: { kind: "running" },
};

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
  lockdown: null,
};

/** Add one "New persistent" row and fill it the way a user would. */
async function fillNewPersistentRow(size: string, sandbox: SandboxView = stopped) {
  render(<VolumesTab sandbox={sandbox} onChanged={() => {}} />);
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
    // The row editors render BELOW the banner — the hint must point there.
    expect(screen.getByText(/fix the invalid volume row below/i)).toBeInTheDocument();
  });

  it("a row with the size left blank disables Save WITHOUT a per-field error — the banner must still say why", async () => {
    // The silent case behind the original report: per-field errors render
    // only for fields the user has typed into, but Save is gated on the whole
    // row. Name + path filled, size empty ⇒ disabled Save and, before this
    // fix, no red text anywhere.
    await fillNewPersistentRow("");

    expect(screen.getByRole("button", { name: /^save changes$/i })).toBeDisabled();
    expect(screen.queryByText(/size must be/i)).not.toBeInTheDocument();
    expect(screen.getByText(/fix the invalid volume row below/i)).toBeInTheDocument();
  });

  it("no restart button is offered for a stopped sandbox", async () => {
    await fillNewPersistentRow("5g");
    expect(screen.queryByRole("button", { name: /restart now/i })).not.toBeInTheDocument();
  });

  it("'Save & restart now' shows progress on ITSELF, not on the neighbouring Save", async () => {
    let releaseAttach: () => void = () => {};
    let releaseRestart: () => void = () => {};
    volumeAttach.mockImplementation(
      () =>
        new Promise<void>((resolve) => {
          releaseAttach = resolve;
        }),
    );
    restart.mockImplementation(
      () =>
        new Promise<void>((resolve) => {
          releaseRestart = resolve;
        }),
    );
    await fillNewPersistentRow("5g", running);
    fireEvent.click(screen.getByRole("button", { name: /save & restart now/i }));

    // While the attach runs the clicked button carries the progress label and
    // the plain Save keeps its own label (disabled, but not "Saving…").
    const restarting = await screen.findByRole("button", { name: /^saving…$/i });
    expect(restarting).toBeDisabled();
    expect(screen.getByRole("button", { name: /^save changes$/i })).toBeDisabled();
    releaseAttach();

    // Then the restart itself: the same button says so until it lands.
    await screen.findByRole("button", { name: /^restarting…$/i });
    releaseRestart();
    await waitFor(() => expect(restart).toHaveBeenCalledWith("management"));
    await waitFor(() =>
      expect(screen.queryByRole("button", { name: /^restarting…$/i })).not.toBeInTheDocument(),
    );
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
