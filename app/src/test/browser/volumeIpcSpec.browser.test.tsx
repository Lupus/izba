/**
 * Browser-mode end-to-end tests for the existing-persistent IPC serialization
 * chain through VolumesTab and NewSandbox.
 *
 * These restore the behavior the original jsdom tests verified — pick an
 * existing volume from the dropdown, fill the path, submit, and assert the IPC
 * mock was called with the exact composite spec string ("archive:/arch:1024m").
 * Radix Select can only be opened in a real browser, so this lives here (the
 * jsdom suite asserts only the render-level trigger presence).
 */
import { render } from "vitest-browser-react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import type { SandboxView } from "@/lib/types";

// ── hoisted IPC mocks (shared by both components) ─────────────────────────────
const { create, inspect, volumeAttach, volumeDetach, restart, volumeList, onCreateProgress } =
  vi.hoisted(() => ({
    create: vi.fn(),
    inspect: vi.fn(),
    volumeAttach: vi.fn(),
    volumeDetach: vi.fn(),
    restart: vi.fn(),
    volumeList: vi.fn(),
    onCreateProgress: vi.fn(),
  }));

vi.mock("@/lib/ipc", () => ({
  api: { create, inspect, volumeAttach, volumeDetach, restart, volumeList },
  onCreateProgress,
}));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn().mockResolvedValue("/picked/ws") }));

import { VolumesTab } from "@/components/VolumesTab";
import { NewSandbox } from "@/components/NewSandbox";

const running: SandboxView = {
  name: "mysbx",
  image: "ubuntu:24.04",
  state: { kind: "running" },
};

beforeEach(() => {
  vi.clearAllMocks();
  inspect.mockResolvedValue({
    name: "mysbx",
    image: "ubuntu:24.04",
    status: "running",
    ports: [],
    volumes: [],
  });
  create.mockResolvedValue("web");
  volumeAttach.mockResolvedValue(undefined);
  volumeDetach.mockResolvedValue(undefined);
  restart.mockResolvedValue(undefined);
  onCreateProgress.mockResolvedValue(() => {});
  volumeList.mockResolvedValue([
    { name: "archive", size_bytes: 1073741824, actual_bytes: 0, referenced_by: [] },
  ]);
});

afterEach(() => {
  vi.clearAllMocks();
});

test("VolumesTab: existing-persistent pick → Save → volumeAttach with composite spec", async () => {
  const screen = await render(<VolumesTab sandbox={running} onChanged={() => {}} />);

  // Add an inline row and switch it to existing-persistent.
  await screen.getByRole("button", { name: /\+ add volume/i }).click();
  await screen.getByRole("radio", { name: /existing/i }).click();

  // Open the Radix Select and pick "archive".
  const trigger = screen.getByRole("combobox", { name: /existing volume/i });
  await expect.element(trigger).toBeVisible();
  await trigger.click();
  await screen.getByRole("option", { name: /archive/i }).click();

  // Fill the guest path.
  await screen.getByLabelText(/volume 1 path/i).fill("/arch");

  // Save changes.
  await screen.getByRole("button", { name: /^save changes$/i }).click();

  // The full chain: archive (1 GiB → 1024 MiB) at /arch → "archive:/arch:1024m".
  await vi.waitFor(() =>
    expect(volumeAttach).toHaveBeenCalledWith("mysbx", "archive:/arch:1024m"),
  );
});

test("NewSandbox: existing-persistent pick → Create → create() with composite spec", async () => {
  const screen = await render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);

  await screen.getByLabelText(/name/i).fill("web");
  await screen.getByLabelText(/workspace/i).fill("/ws");

  await screen.getByRole("button", { name: /\+ add volume/i }).click();
  await screen.getByRole("radio", { name: /existing/i }).click();

  const trigger = screen.getByRole("combobox", { name: /existing volume/i });
  await expect.element(trigger).toBeVisible();
  await trigger.click();
  await screen.getByRole("option", { name: /archive/i }).click();

  await screen.getByLabelText(/volume 1 path/i).fill("/arch");

  await screen.getByRole("button", { name: /create/i }).click();

  await vi.waitFor(() =>
    expect(create).toHaveBeenCalledWith(
      expect.objectContaining({ volumes: ["archive:/arch:1024m"] }),
    ),
  );
});
