import { useEffect, useState } from "react";
import type { SandboxView, VolumeSpec } from "../lib/types";
import { api } from "../lib/ipc";
import {
  type VolumeRow,
  isValidVolName,
  isValidVolPath,
  isValidVolSize,
  isBlankVolRow,
  isValidVolRow,
} from "../lib/volumevalidate";

interface Props {
  sandbox: SandboxView;
  onChanged: () => void;
}

/** Build the volumeAttach spec string: "[name:]path:size" */
function buildSpec(row: VolumeRow): string {
  const name = row.name.trim();
  const path = row.path.trim();
  const size = row.size.trim();
  return name ? `${name}:${path}:${size}` : `${path}:${size}`;
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

interface NewRow {
  row: VolumeRow;
  /** Per-field validation error message, or null if the field is okay. */
  nameErr: string | null;
  pathErr: string | null;
  sizeErr: string | null;
}

export function VolumesTab({ sandbox, onChanged }: Props) {
  const [seeded, setSeeded] = useState<SeededRow[]>([]);
  const [newRows, setNewRows] = useState<NewRow[]>([]);
  const [dirty, setDirty] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const running = sandbox.state.kind !== "stopped";
  const name = sandbox.name;

  async function load() {
    try {
      const detail = await api.inspect(name);
      setSeeded(detail.volumes.map((v) => ({ spec: v, removed: false })));
      setNewRows([]);
      setDirty(false);
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
      setSeeded(detail.volumes.map((v) => ({ spec: v, removed: false })));
      setNewRows([]);
      setDirty(false);
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

  function markDirty() {
    setDirty(true);
  }

  function removeSeeded(idx: number) {
    setSeeded((prev) => prev.map((s, i) => (i === idx ? { ...s, removed: true } : s)));
    markDirty();
  }

  function restoreSeeded(idx: number) {
    setSeeded((prev) => prev.map((s, i) => (i === idx ? { ...s, removed: false } : s)));
    // re-check dirty: any removed row still removed?
    setDirty(true);
  }

  function addRow() {
    setNewRows((prev) => [
      ...prev,
      { row: { name: "", path: "", size: "" }, nameErr: null, pathErr: null, sizeErr: null },
    ]);
    markDirty();
  }

  function removeNewRow(idx: number) {
    setNewRows((prev) => prev.filter((_, i) => i !== idx));
    // if no more changes dirty might be wrong, but simpler to keep dirty=true
    // (user can discard by navigating away)
  }

  function updateNewRow(idx: number, field: keyof VolumeRow, value: string) {
    setNewRows((prev) =>
      prev.map((nr, i) => {
        if (i !== idx) return nr;
        const row = { ...nr.row, [field]: value };
        return { ...nr, row };
      }),
    );
  }

  /** Save pending edits. Returns true if the save succeeded (no errors). */
  async function save(): Promise<boolean> {
    // Validate all new rows (ignore blank rows)
    let hasErr = false;
    const validated = newRows.map((nr) => {
      if (isBlankVolRow(nr.row)) return nr;
      const nameErr = isValidVolName(nr.row.name.trim())
        ? null
        : "Name must be lowercase alphanumeric, _, or -.";
      const pathErr = isValidVolPath(nr.row.path.trim())
        ? null
        : "Path must start with / and contain no commas.";
      const sizeErr = isValidVolSize(nr.row.size.trim())
        ? null
        : "Size must be a positive integer followed by g/m/G/M.";
      if (nameErr || pathErr || sizeErr) hasErr = true;
      return { ...nr, nameErr, pathErr, sizeErr };
    });
    if (hasErr) {
      setNewRows(validated);
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
      const toAttach = newRows.filter((nr) => !isBlankVolRow(nr.row) && isValidVolRow(nr.row));
      for (const nr of toAttach) {
        await api.volumeAttach(name, buildSpec(nr.row));
      }
      succeeded = true;
    } catch (e) {
      saveError = e instanceof Error ? e.message : String(e);
    } finally {
      // Always re-sync rows to daemon truth (success or partial failure).
      // Use refreshRows() instead of load() so a save error is not cleared
      // by the re-sync; on success load() would also work but refreshRows()
      // is consistent. Set the save error AFTER refreshRows so it is the
      // final state.
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

  const inputCls = "rounded border border-line px-2 py-1 text-sm font-mono";

  return (
    <div className="flex flex-col gap-4">
      {error && <div className="text-sm text-warn">{error}</div>}

      {/* Dirty banner */}
      {dirty && (
        <div className="flex items-center gap-3 rounded-lg border border-accent/30 bg-accent/5 px-3 py-2 text-sm">
          <span className="flex-1">These changes apply on next restart.</span>
          <button
            type="button"
            disabled={saving}
            onClick={() => void save()}
            className="rounded-lg bg-accent px-3 py-1.5 text-sm font-semibold text-white disabled:opacity-50"
          >
            Save
          </button>
          {running && (
            <button
              type="button"
              disabled={saving}
              onClick={() => void restartNow()}
              className="rounded-lg border border-line px-3 py-1.5 text-sm hover:bg-hover disabled:opacity-50"
            >
              Restart now
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
                  (isPersistent
                    ? "bg-accent/10 text-accent"
                    : "bg-hover text-ink-2")
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
                  aria-label={`Remove ${s.spec.guest_path}`}
                  onClick={() => removeSeeded(i)}
                  className="rounded border border-warn/40 px-2 py-1 text-xs text-warn hover:bg-warn/5"
                >
                  Remove
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
            {isPersistent && !s.removed && (
              <p className="text-xs text-ink-3">
                Persistent volumes are single-writer — only one sandbox may attach this volume at a
                time.
              </p>
            )}
          </div>
        );
      })}

      {/* New rows being added */}
      {newRows.map((nr, i) => (
        <div key={`new-${i}`} className="flex flex-col gap-2 rounded-lg border border-line p-3">
          <div className="flex items-center gap-2">
            <label className="w-24 shrink-0 text-xs font-semibold text-ink-2" htmlFor={`vol-name-${i}`}>
              Volume name
            </label>
            <input
              id={`vol-name-${i}`}
              aria-label="Volume name"
              value={nr.row.name}
              onChange={(e) => updateNewRow(i, "name", e.target.value)}
              placeholder="cache (empty = ephemeral)"
              className={inputCls + " flex-1"}
            />
          </div>
          {nr.nameErr && <span className="text-xs text-warn">{nr.nameErr}</span>}

          <div className="flex items-center gap-2">
            <label className="w-24 shrink-0 text-xs font-semibold text-ink-2" htmlFor={`vol-path-${i}`}>
              Guest path
            </label>
            <input
              id={`vol-path-${i}`}
              aria-label="Guest path"
              value={nr.row.path}
              onChange={(e) => updateNewRow(i, "path", e.target.value)}
              placeholder="/data"
              className={inputCls + " flex-1"}
            />
          </div>
          {nr.pathErr && <span className="text-xs text-warn">{nr.pathErr}</span>}

          <div className="flex items-center gap-2">
            <label className="w-24 shrink-0 text-xs font-semibold text-ink-2" htmlFor={`vol-size-${i}`}>
              Size
            </label>
            <input
              id={`vol-size-${i}`}
              aria-label="Size"
              value={nr.row.size}
              onChange={(e) => updateNewRow(i, "size", e.target.value)}
              placeholder="1g"
              className={inputCls + " w-24"}
            />
          </div>
          {nr.sizeErr && <span className="text-xs text-warn">{nr.sizeErr}</span>}

          <div className="flex justify-end">
            <button
              type="button"
              onClick={() => removeNewRow(i)}
              className="rounded border border-warn/40 px-2 py-1 text-xs text-warn hover:bg-warn/5"
            >
              Cancel
            </button>
          </div>
        </div>
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
