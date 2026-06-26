import { useEffect, useRef, useState } from "react";
import type { SandboxView, VolumeSpec, VolumeInfo } from "../lib/types";
import { api } from "../lib/ipc";
import {
  type VolumeRow,
  defaultVolumeRow,
  buildVolSpec,
  freeVolumes as computeFreeVolumes,
  isBlankVolRow,
  isValidVolRow,
  usedExistingNames,
  volNameError,
  volPathError,
  volSizeError,
  volPickError,
} from "../lib/volumevalidate";
import { VolumeRowEditor } from "./VolumeRowEditor";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { EditableList } from "@/components/ui/editable-list";

interface Props {
  sandbox: SandboxView;
  onChanged: () => void;
}

/** Format bytes into a human-readable string (best-effort, display only). */
function fmtBytes(n: number): string {
  if (n >= 1073741824) return `${(n / 1073741824).toFixed(0)} GiB`;
  if (n >= 1048576) return `${(n / 1048576).toFixed(0)} MiB`;
  return `${n} B`;
}

interface SeededRow {
  spec: VolumeSpec;
  removed: boolean;
}

export function VolumesTab({ sandbox, onChanged }: Props) {
  const [seeded, setSeeded] = useState<SeededRow[]>([]);
  const [volumeRows, setVolumeRows] = useState<VolumeRow[]>([]);
  const [allVolumes, setAllVolumes] = useState<VolumeInfo[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const loadedRef = useRef<VolumeSpec[]>([]);

  const running = sandbox.state.kind !== "stopped";
  const name = sandbox.name;

  async function load() {
    try {
      const detail = await api.inspect(name);
      loadedRef.current = detail.volumes;
      setSeeded(detail.volumes.map((v) => ({ spec: v, removed: false })));
      setVolumeRows([]);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  /**
   * Re-fetch rows from the daemon without touching the error state.
   * Used by save()'s finally block so a save error stays visible even
   * after the UI has been re-synced to daemon truth.
   */
  async function refreshRows() {
    try {
      const detail = await api.inspect(name);
      loadedRef.current = detail.volumes;
      setSeeded(detail.volumes.map((v) => ({ spec: v, removed: false })));
      setVolumeRows([]);
      // intentionally NOT calling setError here
    } catch {
      // silently ignore — the save error (if any) is already set and visible;
      // a failing re-sync is non-fatal.
    }
  }

  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [name]);

  useEffect(() => {
    void (async () => {
      try {
        setAllVolumes(await api.volumeList());
      } catch {
        // Non-fatal: the existing-persistent dropdown simply shows empty.
      }
    })();
  }, []);

  // Free volumes available to attach: not referenced by any sandbox, and not
  // already seeded (non-removed) on THIS sandbox, and not already in volumeRows
  // as existing_persistent (for other rows).
  const seededNames = new Set(
    seeded.filter((s) => !s.removed && s.spec.name).map((s) => s.spec.name as string),
  );

  function freeVolumesFor(rowIdx: number): VolumeInfo[] {
    return computeFreeVolumes(allVolumes, seededNames, usedExistingNames(volumeRows, rowIdx));
  }

  const addVolume = () => setVolumeRows((rows) => [...rows, defaultVolumeRow()]);
  const removeVolume = (i: number) => setVolumeRows((rows) => rows.filter((_, j) => j !== i));
  const setVolumeRow = (i: number, row: VolumeRow) =>
    setVolumeRows((rows) => rows.map((r, j) => (j === i ? row : r)));

  // Derived dirty: seeded set changed from what was loaded, OR non-blank inline rows exist.
  const seededDesired = seeded.filter((s) => !s.removed).map((s) => s.spec);
  const dirty =
    JSON.stringify(seededDesired) !== JSON.stringify(loadedRef.current) ||
    volumeRows.some((r) => !isBlankVolRow(r));

  const volumesInvalid = volumeRows.some((r) => !isBlankVolRow(r) && !isValidVolRow(r));

  function removeSeeded(idx: number) {
    setSeeded((prev) => prev.map((s, i) => (i === idx ? { ...s, removed: true } : s)));
  }

  function restoreSeeded(idx: number) {
    setSeeded((prev) => prev.map((s, i) => (i === idx ? { ...s, removed: false } : s)));
  }

  /** Save pending edits. Returns true if the save succeeded (no errors). */
  async function save(): Promise<boolean> {
    if (volumesInvalid) return false;
    setSaving(true);
    setError(null);
    let succeeded = false;
    let saveError: string | null = null;
    try {
      // Detach removed seeded rows
      const toDetach = seeded.filter((s) => s.removed);
      for (const s of toDetach) {
        await api.volumeDetach(name, s.spec.guest_path);
      }
      // Attach valid inline rows (only non-blank, validated rows).
      // Use allVolumes (not freeVolumes) so that existing_persistent size lookup still
      // works even if the volume was removed from the free list by row exclusion.
      for (const r of volumeRows.filter((r) => !isBlankVolRow(r))) {
        await api.volumeAttach(name, buildVolSpec(r, allVolumes));
      }
      succeeded = true;
    } catch (e) {
      saveError = e instanceof Error ? e.message : String(e);
    } finally {
      // Always re-sync rows to daemon truth (success or partial failure).
      // Use refreshRows() instead of load() so a save error is not cleared
      // by the re-sync; set the save error AFTER refreshRows so it is final.
      await refreshRows();
      if (saveError !== null) {
        setError(saveError);
      }
      setSaving(false);
    }
    return succeeded;
  }

  async function restartNow() {
    // Save pending edits first; abort restart if save failed
    const saved = await save();
    if (!saved) return;
    try {
      await api.restart(name);
      onChanged();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <div className="flex flex-col gap-4">
      {error && <div className="text-sm text-destructive">{error}</div>}

      {/* Dirty banner */}
      {dirty && (
        <div className="flex items-center gap-3 rounded-lg border border-primary/30 bg-primary/5 px-3 py-2 text-sm">
          <span className="flex-1">
            Unsaved changes.{" "}
            <span className="text-muted-foreground-2">
              Changes are saved to the sandbox config and applied on next restart.
            </span>
          </span>
          <Button
            type="button"
            variant="default"
            size="sm"
            disabled={saving || volumesInvalid}
            onClick={() => void save()}
          >
            Save changes
          </Button>
          {running && (
            <Button
              type="button"
              variant="secondary"
              size="sm"
              disabled={saving || volumesInvalid}
              onClick={() => void restartNow()}
            >
              Save &amp; restart now
            </Button>
          )}
        </div>
      )}

      {/* Seeded rows (from inspect) */}

      {seeded.map((s, i) => {
        const isPersistent = s.spec.name !== null;
        return (
          <div
            key={`seeded-${i}`}
            className={
              "flex flex-col gap-1 rounded-lg border p-3 " +
              (s.removed ? "border-destructive/30 bg-destructive/5 opacity-60" : "border-border")
            }
          >
            <div className="flex items-center gap-2">
              <span className="flex-1 font-mono text-sm">{s.spec.guest_path}</span>
              <Badge
                variant={isPersistent ? "default" : "secondary"}
                title={
                  isPersistent
                    ? "Persistent volumes are single-writer — only one sandbox may attach this volume at a time."
                    : undefined
                }
              >
                {isPersistent ? "persistent" : "ephemeral"}
              </Badge>
              {isPersistent && s.spec.name && (
                <span className="font-mono text-xs text-muted-foreground">{s.spec.name}</span>
              )}
              <span className="text-xs text-muted-foreground-2">{fmtBytes(s.spec.size_bytes)}</span>
              {!s.removed ? (
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  aria-label={
                    isPersistent
                      ? `Detach ${s.spec.guest_path}`
                      : `Remove ${s.spec.guest_path}`
                  }
                  onClick={() => removeSeeded(i)}
                >
                  {isPersistent ? "Detach" : "Remove"}
                </Button>
              ) : (
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={() => restoreSeeded(i)}
                >
                  Undo
                </Button>
              )}
            </div>
          </div>
        );
      })}

      {/* Inline new-volume rows */}
      <EditableList
        density="card"
        items={volumeRows}
        renderRow={(row, i) => {
          const nameErr =
            row.kind === "new_persistent" && row.name.trim() !== ""
              ? volNameError(row.kind, row.name.trim())
              : null;
          const pathErr = row.path.trim() !== "" ? volPathError(row.path.trim()) : null;
          const sizeErr =
            (row.kind === "ephemeral" || row.kind === "new_persistent") && row.size.trim() !== ""
              ? volSizeError(row.kind, row.size.trim())
              : null;
          const pickErr =
            row.kind === "existing_persistent" && row.path.trim() !== ""
              ? volPickError(row.kind, row.selectedVolName)
              : null;
          return (
            <>
              <VolumeRowEditor
                row={row}
                index={i}
                freeVolumes={freeVolumesFor(i)}
                onChange={(r) => setVolumeRow(i, r)}
              />
              {nameErr && <span className="text-xs text-destructive">{nameErr}</span>}
              {pathErr && <span className="text-xs text-destructive">{pathErr}</span>}
              {sizeErr && <span className="text-xs text-destructive">{sizeErr}</span>}
              {pickErr && <span className="text-xs text-destructive">{pickErr}</span>}
            </>
          );
        }}
        onAdd={addVolume}
        onRemove={removeVolume}
        addLabel="+ Add volume"
        emptyHint="No volumes — add one to mount it."
        rowAriaLabel={(_, i) => `Remove volume ${i + 1}`}
      />
    </div>
  );
}
