import { useEffect, useRef, useState } from "react";
import type { SandboxView, VolumeSpec, VolumeInfo } from "../lib/types";
import { api } from "../lib/ipc";
import {
  type VolumeRow,
  defaultVolumeRow,
  buildVolSpec,
  isBlankVolRow,
  isValidVolRow,
} from "../lib/volumevalidate";
import { VolumeRowEditor } from "./VolumeRowEditor";

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
  const [newRows, setNewRows] = useState<VolumeRow[]>([]);
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
      setNewRows([]);
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
      setNewRows([]);
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
  // already seeded (non-removed) on THIS sandbox.
  const seededNames = new Set(
    seeded.filter((s) => !s.removed && s.spec.name).map((s) => s.spec.name as string),
  );
  const freeVolumes = allVolumes.filter(
    (v) => v.referenced_by.length === 0 && !seededNames.has(v.name),
  );

  // Derived dirty: seeded set changed from what was loaded, OR new rows are staged.
  const seededDesired = seeded.filter((s) => !s.removed).map((s) => s.spec);
  const dirty =
    JSON.stringify(seededDesired) !== JSON.stringify(loadedRef.current) ||
    newRows.length > 0;

  function removeSeeded(idx: number) {
    setSeeded((prev) => prev.map((s, i) => (i === idx ? { ...s, removed: true } : s)));
  }

  function restoreSeeded(idx: number) {
    setSeeded((prev) => prev.map((s, i) => (i === idx ? { ...s, removed: false } : s)));
  }

  function addRow() {
    setNewRows((prev) => [...prev, defaultVolumeRow()]);
  }

  function removeNewRow(idx: number) {
    setNewRows((prev) => prev.filter((_, i) => i !== idx));
  }

  function updateNewRow(idx: number, row: VolumeRow) {
    setNewRows((prev) => prev.map((r, i) => (i === idx ? row : r)));
  }

  /** Save pending edits. Returns true if the save succeeded (no errors). */
  async function save(): Promise<boolean> {
    // Validate all new rows (ignore blank rows). A started-but-invalid row
    // blocks the save.
    const hasErr = newRows.some((r) => !isBlankVolRow(r) && !isValidVolRow(r));
    if (hasErr) {
      setError("Each volume needs valid fields for its type.");
      return false;
    }

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
      // Attach new valid rows
      const toAttach = newRows.filter((r) => !isBlankVolRow(r) && isValidVolRow(r));
      for (const r of toAttach) {
        await api.volumeAttach(name, buildVolSpec(r, freeVolumes));
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
      {error && <div className="text-sm text-warn">{error}</div>}

      {/* Dirty banner */}
      {dirty && (
        <div className="flex items-center gap-3 rounded-lg border border-accent/30 bg-accent/5 px-3 py-2 text-sm">
          <span className="flex-1">
            Unsaved changes.{" "}
            <span className="text-ink-3">
              Changes are saved to the sandbox config and applied on next restart.
            </span>
          </span>
          <button
            type="button"
            disabled={saving}
            onClick={() => void save()}
            className="rounded-lg bg-accent px-3 py-1.5 text-sm font-semibold text-white disabled:opacity-50"
          >
            Save changes
          </button>
          {running && (
            <button
              type="button"
              disabled={saving}
              onClick={() => void restartNow()}
              className="rounded-lg border border-line px-3 py-1.5 text-sm hover:bg-hover disabled:opacity-50"
            >
              Save &amp; restart now
            </button>
          )}
        </div>
      )}

      {/* Seeded rows (from inspect) */}
      {seeded.length === 0 && newRows.length === 0 && (
        <div className="text-sm text-ink-3">No volumes attached.</div>
      )}

      {seeded.map((s, i) => {
        const isPersistent = s.spec.name !== null;
        return (
          <div
            key={`seeded-${i}`}
            className={
              "flex flex-col gap-1 rounded-lg border p-3 " +
              (s.removed ? "border-warn/30 bg-warn/5 opacity-60" : "border-line")
            }
          >
            <div className="flex items-center gap-2">
              <span className="flex-1 font-mono text-sm">{s.spec.guest_path}</span>
              <span
                className={
                  "rounded px-1.5 py-0.5 text-xs font-semibold " +
                  (isPersistent ? "bg-accent/10 text-accent" : "bg-hover text-ink-2")
                }
                title={
                  isPersistent
                    ? "Persistent volumes are single-writer — only one sandbox may attach this volume at a time."
                    : undefined
                }
              >
                {isPersistent ? "persistent" : "ephemeral"}
              </span>
              {isPersistent && s.spec.name && (
                <span className="font-mono text-xs text-ink-2">{s.spec.name}</span>
              )}
              <span className="text-xs text-ink-3">{fmtBytes(s.spec.size_bytes)}</span>
              {!s.removed ? (
                <button
                  type="button"
                  aria-label={`Detach ${s.spec.guest_path}`}
                  onClick={() => removeSeeded(i)}
                  className="rounded border border-warn/40 px-2 py-1 text-xs text-warn hover:bg-warn/5"
                >
                  Detach
                </button>
              ) : (
                <button
                  type="button"
                  onClick={() => restoreSeeded(i)}
                  className="rounded border border-line px-2 py-1 text-xs text-ink-2 hover:bg-hover"
                >
                  Undo
                </button>
              )}
            </div>
          </div>
        );
      })}

      {/* New rows being added */}
      {newRows.map((r, i) => (
        <VolumeRowEditor
          key={`new-${i}`}
          row={r}
          index={i}
          freeVolumes={freeVolumes}
          onChange={(row) => updateNewRow(i, row)}
          onRemove={() => removeNewRow(i)}
        />
      ))}

      <div>
        <button
          type="button"
          onClick={addRow}
          className="rounded-lg border border-line px-3 py-1.5 text-sm hover:bg-hover"
        >
          Add volume
        </button>
      </div>
    </div>
  );
}
