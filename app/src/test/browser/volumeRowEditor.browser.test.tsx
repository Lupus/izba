/**
 * Browser-mode interaction tests for VolumeRowEditor.
 *
 * Radix Select cannot be opened in jsdom (no pointer-capture, no ResizeObserver,
 * pointer-events:none body suppression not implemented).  These tests run in real
 * Chromium via Vitest Browser Mode so the dropdown actually opens and option
 * clicks register.
 *
 * VolumeRowEditor takes plain props (no Tauri IPC), so no mock is needed.
 */
import { useState } from "react";
import { render } from "vitest-browser-react";
import { expect, test, vi } from "vitest";
import type { VolumeRow } from "@/lib/volumevalidate";
import type { VolumeInfo } from "@/lib/types";
import { VolumeRowEditor } from "@/components/VolumeRowEditor";

// ── fixtures ─────────────────────────────────────────────────────────────────

const FREE_VOLUMES: VolumeInfo[] = [
  { name: "archive", size_bytes: 1073741824, actual_bytes: 0, referenced_by: [] },
  { name: "cache", size_bytes: 536870912, actual_bytes: 0, referenced_by: [] },
];

function makeRow(overrides: Partial<VolumeRow> = {}): VolumeRow {
  return {
    kind: "ephemeral",
    name: "",
    path: "",
    size: "",
    selectedVolName: "",
    ...overrides,
  };
}

// Minimal stateful wrapper so VolumeRowEditor is controlled and onChange fires.
function EditorWrapper({
  initialRow,
  freeVolumes,
  onChange,
  onRemove,
}: {
  initialRow: VolumeRow;
  freeVolumes: VolumeInfo[];
  onChange: (row: VolumeRow) => void;
  onRemove: () => void;
}) {
  const [row, setRow] = useState(initialRow);
  return (
    <VolumeRowEditor
      row={row}
      freeVolumes={freeVolumes}
      onChange={(r) => {
        setRow(r);
        onChange(r);
      }}
      onRemove={onRemove}
      index={0}
    />
  );
}

// ── tests ─────────────────────────────────────────────────────────────────────

test("VolumeRowEditor: SegmentedControl switches volume type", async () => {
  const onChange = vi.fn();
  const screen = await render(
    <EditorWrapper
      initialRow={makeRow()}
      freeVolumes={FREE_VOLUMES}
      onChange={onChange}
      onRemove={() => {}}
    />,
  );

  // Default kind is ephemeral — the radiogroup should be visible
  await expect.element(screen.getByRole("radiogroup")).toBeVisible();

  // Click "New persistent" radio
  await screen.getByRole("radio", { name: /new persistent/i }).click();

  // onChange should have been called with the new kind
  expect(onChange).toHaveBeenCalledWith(
    expect.objectContaining({ kind: "new_persistent" }),
  );
});

test("VolumeRowEditor: Radix Select opens and picks an existing volume", async () => {
  const onChange = vi.fn();
  const screen = await render(
    <EditorWrapper
      initialRow={makeRow({ kind: "existing_persistent" })}
      freeVolumes={FREE_VOLUMES}
      onChange={onChange}
      onRemove={() => {}}
    />,
  );

  // SelectTrigger should be visible with the accessible name
  const trigger = screen.getByRole("combobox", { name: /existing volume/i });
  await expect.element(trigger).toBeVisible();

  // Open the dropdown
  await trigger.click();

  // Options should appear in the portal
  const archiveOption = screen.getByRole("option", { name: /archive/i });
  await expect.element(archiveOption).toBeVisible();

  // Click the option — Radix calls onValueChange("archive")
  await archiveOption.click();

  // onChange should have been called with selectedVolName = "archive"
  expect(onChange).toHaveBeenCalledWith(
    expect.objectContaining({ selectedVolName: "archive" }),
  );
});

test("VolumeRowEditor: switching to existing_persistent shows the Select trigger", async () => {
  const onChange = vi.fn();
  const screen = await render(
    <EditorWrapper
      initialRow={makeRow()}
      freeVolumes={FREE_VOLUMES}
      onChange={onChange}
      onRemove={() => {}}
    />,
  );

  // Switch to existing persistent
  await screen.getByRole("radio", { name: /existing/i }).click();

  // Trigger should now be present
  await expect
    .element(screen.getByRole("combobox", { name: /existing volume/i }))
    .toBeVisible();
});
