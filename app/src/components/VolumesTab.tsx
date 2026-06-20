import { useEffect, useRef, useState } from "react";
import type { SandboxView, VolumeSpec, VolumeInfo } from "../lib/types";
import { api } from "../lib/ipc";
import {
  type VolumeRow,
  defaultVolumeRow,
  buildVolSpec,
  isValidVolRow,
  volNameError,
  volPathError,
  volSizeError,
  volPickError,
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
  const [toAdd, setToAdd] = useState<VolumeRow[]>([]);
  const [draft, setDraft] = useState<VolumeRow>(defaultVolumeRow());
  const [addAttempted, setAddAttempted] = useState(false);
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
      setToAdd([]);
      setDraft(defaultVolumeRow());
      setAddAttempted(false);
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
      setToAdd([]);
      setDraft(defaultVolumeRow());
      setAddAttempted(false);
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
  // already seeded (non-removed) on THIS sandbox, and not already in toAdd.
  const seededNames = new Set(
    seeded.filter((s) => !s.removed && s.spec.name).map((s) => s.spec.name as string),
  );
  const toAddNames = new Set(
    toAdd.filter((r) => r.kind === "existing_persistent").map((r) => r.selectedVolName),
  );
  const freeVolumes = allVolumes.filter(
    (v) => v.referenced_by.length === 0 && !seededNames.has(v.name) && !toAddNames.has(v.name),
  );

  // Derived dirty: seeded set changed from what was loaded, OR staged volumes exist.
  const seededDesired = seeded.filter((s) => !s.removed).map((s) => s.spec);
  const dirty =
    JSON.stringify(seededDesired) !== JSON.stringify(loadedRef.current) ||
    toAdd.length > 0;

  // Derived inline error messages — only shown when addAttempted is true.
  const draftNameErr = addAttempted ? volNameError(draft.kind, draft.name.trim()) : null;
  const draftPathErr = addAttempted ? volPathError(draft.path.trim()) : null;
  const draftSizeErr = addAttempted ? volSizeError(draft.kind, draft.size.trim()) : null;
  const draftPickErr = addAttempted ? volPickError(draft.kind, draft.selectedVolName) : null;

  function removeSeeded(idx: number) {
    setSeeded((prev) => prev.map((s, i) => (i === idx ? { ...s, removed: true } : s)));
  }

  function restoreSeeded(idx: number) {
    setSeeded((prev) => prev.map((s, i) => (i === idx ? { ...s, removed: false } : s)));
  }

  function handleAdd() {
    setAddAttempted(true);
    if (!isValidVolRow(draft)) return; // keep draft, errors now shown
    setToAdd((prev) => [...prev, draft]);
    setDraft(defaultVolumeRow());
    setAddAttempted(false);
  }

  function removeToAdd(idx: number) {
    setToAdd((prev) => prev.filter((_, i) => i !== idx));
  }

  /** Save pending edits. Returns true if the save succeeded (no errors). */
  async function save(): Promise<boolean> {
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
      // Attach staged valid rows (toAdd only contains valid rows — validated at Add time).
      // Use allVolumes (not freeVolumes) so that existing_persistent size lookup still
      // works even though the staged volume was removed from freeVolumes by toAddNames.
      for (const r of toAdd) {
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
      {seeded.length === 0 && toAdd.length === 0 && (
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

      {/* Staged volumes (validated, waiting to be saved) */}
      {toAdd.map((r, i) => (
        <div
          key={`staged-${i}`}
          className="flex items-center gap-2 rounded-lg border border-line px-3 py-2 text-sm"
        >
          <span className="flex-1 font-mono">{r.path}</span>
          <span className="text-xs text-ink-2">
            {r.kind === "ephemeral"
              ? "ephemeral"
              : r.kind === "new_persistent"
                ? `persistent · ${r.name}`
                : `existing · ${r.selectedVolName}`}
          </span>
          {(r.kind === "ephemeral" || r.kind === "new_persistent") && (
            <span className="text-xs text-ink-3">{r.size}</span>
          )}
          <button
            type="button"
            aria-label={`Remove staged volume ${r.path}`}
            onClick={() => removeToAdd(i)}
            className="text-ink-3 hover:text-warn"
          >
            ✕
          </button>
        </div>
      ))}

      {/* Draft editor — always visible */}
      <div className="flex flex-col gap-2">
        <VolumeRowEditor
          row={draft}
          index={0}
          freeVolumes={freeVolumes}
          onChange={setDraft}
          onRemove={() => {
            setDraft(defaultVolumeRow());
            setAddAttempted(false);
          }}
        />
        {/* Inline error messages — shown after first Add attempt */}
        {draftNameErr && <span className="text-xs text-warn">{draftNameErr}</span>}
        {draftPathErr && <span className="text-xs text-warn">{draftPathErr}</span>}
        {draftSizeErr && <span className="text-xs text-warn">{draftSizeErr}</span>}
        {draftPickErr && <span className="text-xs text-warn">{draftPickErr}</span>}
        <div className="flex gap-2">
          <button
            type="button"
            onClick={handleAdd}
            className="rounded-lg border border-line px-3 py-1.5 text-sm hover:bg-hover"
          >
            Add
          </button>
        </div>
      </div>
    </div>
  );
}
