import type { VolumeInfo } from "../lib/types";
import {
  type VolumeKind,
  type VolumeRow,
  isValidVolNameNonEmpty,
  isValidVolPath,
  isValidVolSize,
} from "../lib/volumevalidate";

interface Props {
  row: VolumeRow;
  /** Already filtered to free, attachable volumes (caller does the filtering). */
  freeVolumes: VolumeInfo[];
  onChange: (row: VolumeRow) => void;
  onRemove: () => void;
  /** Zero-based; used for aria-labels like "Volume 1 name". */
  index: number;
}

/** Format bytes into a human-readable string (best-effort, display only). */
function fmtBytes(n: number): string {
  if (n >= 1073741824) return `${(n / 1073741824).toFixed(0)} GiB`;
  if (n >= 1048576) return `${(n / 1048576).toFixed(0)} MiB`;
  return `${n} B`;
}

const KINDS: { kind: VolumeKind; label: string }[] = [
  { kind: "ephemeral", label: "Ephemeral" },
  { kind: "new_persistent", label: "New persistent" },
  { kind: "existing_persistent", label: "Existing persistent" },
];

/** One editable new-volume row with a 3-way type selector. */
export function VolumeRowEditor({ row, freeVolumes, onChange, onRemove, index }: Props) {
  const n = index + 1;
  const inputCls = "rounded border border-line px-2 py-1 text-sm font-mono";

  const setKind = (kind: VolumeKind) => onChange({ ...row, kind });
  const set = (patch: Partial<VolumeRow>) => onChange({ ...row, ...patch });

  const showName = row.kind === "new_persistent";
  const showSizeInput = row.kind === "ephemeral" || row.kind === "new_persistent";
  const isExisting = row.kind === "existing_persistent";

  // Per-field validity (only flag once the user has typed something).
  const nameBad = showName && row.name.trim() !== "" && !isValidVolNameNonEmpty(row.name.trim());
  const pathBad = row.path.trim() !== "" && !isValidVolPath(row.path.trim());
  const sizeBad = showSizeInput && row.size.trim() !== "" && !isValidVolSize(row.size.trim());

  const selectedVol = freeVolumes.find((v) => v.name === row.selectedVolName);

  return (
    <div className="flex flex-col gap-2 rounded-lg border border-line p-3">
      {/* Segmented type selector */}
      <div className="flex w-fit overflow-hidden rounded-lg border border-line text-xs">
        {KINDS.map(({ kind, label }) => {
          const active = row.kind === kind;
          return (
            <button
              key={kind}
              type="button"
              aria-pressed={active}
              onClick={() => setKind(kind)}
              className={
                "px-3 py-1.5 " +
                (active ? "bg-accent text-white" : "text-ink-2 hover:bg-hover")
              }
            >
              {label}
            </button>
          );
        })}
      </div>

      {/* Existing-persistent: dropdown of free named volumes */}
      {isExisting && (
        <div className="flex items-center gap-2">
          <label
            className="w-24 shrink-0 text-xs font-semibold text-ink-2"
            htmlFor={`vol-existing-${index}`}
          >
            Volume
          </label>
          {freeVolumes.length === 0 ? (
            <span className="flex-1 text-xs text-ink-3">No free volumes available</span>
          ) : (
            <select
              id={`vol-existing-${index}`}
              aria-label="Existing volume"
              value={row.selectedVolName}
              onChange={(e) => set({ selectedVolName: e.target.value })}
              className={inputCls + " flex-1"}
            >
              <option value="">Select a volume…</option>
              {freeVolumes.map((v) => (
                <option key={v.name} value={v.name}>
                  {v.name} ({fmtBytes(v.size_bytes)})
                </option>
              ))}
            </select>
          )}
        </div>
      )}

      {/* New-persistent: free-input name */}
      {showName && (
        <div className="flex items-center gap-2">
          <label
            className="w-24 shrink-0 text-xs font-semibold text-ink-2"
            htmlFor={`vol-name-${index}`}
          >
            Volume name
          </label>
          <input
            id={`vol-name-${index}`}
            aria-label={`Volume ${n} name`}
            value={row.name}
            onChange={(e) => set({ name: e.target.value })}
            placeholder="cache"
            className={inputCls + " flex-1 " + (nameBad ? "border-warn" : "")}
          />
        </div>
      )}

      {/* Guest path (all kinds) */}
      <div className="flex items-center gap-2">
        <label
          className="w-24 shrink-0 text-xs font-semibold text-ink-2"
          htmlFor={`vol-path-${index}`}
        >
          Guest path
        </label>
        <input
          id={`vol-path-${index}`}
          aria-label={`Volume ${n} path`}
          value={row.path}
          onChange={(e) => set({ path: e.target.value })}
          placeholder="/data"
          className={inputCls + " flex-1 " + (pathBad ? "border-warn" : "")}
        />
      </div>

      {/* Size: editable for ephemeral/new, read-only display for existing */}
      <div className="flex items-center gap-2">
        <label
          className="w-24 shrink-0 text-xs font-semibold text-ink-2"
          htmlFor={isExisting ? undefined : `vol-size-${index}`}
        >
          Size
        </label>
        {isExisting ? (
          <span className="flex-1 font-mono text-sm text-ink-2">
            {selectedVol ? fmtBytes(selectedVol.size_bytes) : "—"}
          </span>
        ) : (
          <input
            id={`vol-size-${index}`}
            aria-label={`Volume ${n} size`}
            value={row.size}
            onChange={(e) => set({ size: e.target.value })}
            placeholder="1g"
            className={inputCls + " w-24 " + (sizeBad ? "border-warn" : "")}
          />
        )}
      </div>

      <div className="flex justify-end">
        <button
          type="button"
          aria-label={`Remove volume ${n}`}
          onClick={onRemove}
          className="rounded border border-warn/40 px-2 py-1 text-xs text-warn hover:bg-warn/5"
        >
          ×
        </button>
      </div>
    </div>
  );
}
