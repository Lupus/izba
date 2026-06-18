import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach } from "vitest";
import type { SandboxView, SandboxDetail } from "../lib/types";

// ── hoisted mocks ─────────────────────────────────────────────────────────────

const { inspect, volumeAttach, volumeDetach, restart } = vi.hoisted(() => ({
  inspect: vi.fn(),
  volumeAttach: vi.fn(),
  volumeDetach: vi.fn(),
  restart: vi.fn(),
}));

vi.mock("../lib/ipc", () => ({
  api: { inspect, volumeAttach, volumeDetach, restart },
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
        volumes: [{ name: null, guest_path: "/tmp/scratch", size_bytes: 536870912 }],
      }),
    );
    render(<VolumesTab sandbox={running} onChanged={noop} />);
    await screen.findByText("ephemeral");
    expect(screen.getByText(/\/tmp\/scratch/)).toBeInTheDocument();
  });
});

describe("VolumesTab — dirty banner", () => {
  it("shows 'applies on next restart' banner when a row is added", async () => {
    render(<VolumesTab sandbox={running} onChanged={noop} />);
    // Wait for inspect to resolve and component to render
    await waitFor(() => expect(inspect).toHaveBeenCalled());

    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    expect(await screen.findByText(/apply on next restart/i)).toBeInTheDocument();
  });

  it("does not show the banner before any edit", async () => {
    render(<VolumesTab sandbox={running} onChanged={noop} />);
    await waitFor(() => expect(inspect).toHaveBeenCalled());
    expect(screen.queryByText(/apply on next restart/i)).not.toBeInTheDocument();
  });
});

describe("VolumesTab — Save: attach a new volume", () => {
  it("calls volumeAttach with correct spec string when a new row is saved", async () => {
    render(<VolumesTab sandbox={running} onChanged={noop} />);
    await waitFor(() => expect(inspect).toHaveBeenCalled());

    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));

    // Fill in the new row
    const nameInput = screen.getByLabelText(/volume name/i);
    const pathInput = screen.getByLabelText(/guest path/i);
    const sizeInput = screen.getByLabelText(/size/i);
    fireEvent.change(nameInput, { target: { value: "cache" } });
    fireEvent.change(pathInput, { target: { value: "/data" } });
    fireEvent.change(sizeInput, { target: { value: "1g" } });

    fireEvent.click(screen.getByRole("button", { name: /^save$/i }));

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
    fireEvent.click(screen.getByRole("button", { name: /remove.*\/data/i }));

    // Banner should appear
    expect(screen.getByText(/apply on next restart/i)).toBeInTheDocument();

    // Save
    fireEvent.click(screen.getByRole("button", { name: /^save$/i }));

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

    expect(await screen.findByRole("button", { name: /restart now/i })).toBeInTheDocument();
  });

  it("does not show Restart now when stopped even if dirty", async () => {
    render(<VolumesTab sandbox={stopped} onChanged={noop} />);
    await waitFor(() => expect(inspect).toHaveBeenCalled());

    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));

    await screen.findByText(/apply on next restart/i);
    expect(screen.queryByRole("button", { name: /restart now/i })).not.toBeInTheDocument();
  });

  it("calls api.restart and onChanged when Restart now is clicked", async () => {
    const onChanged = vi.fn();
    render(<VolumesTab sandbox={running} onChanged={onChanged} />);
    await waitFor(() => expect(inspect).toHaveBeenCalled());

    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));

    const btn = await screen.findByRole("button", { name: /restart now/i });
    fireEvent.click(btn);

    await waitFor(() => expect(restart).toHaveBeenCalledWith("mysbx"));
    await waitFor(() => expect(onChanged).toHaveBeenCalled());
  });
});
