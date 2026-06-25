import type { VolumeInfo } from "../lib/types";
import {
  type VolumeKind,
  type VolumeRow,
  isValidVolNameNonEmpty,
  isValidVolPath,
  isValidVolSize,
} from "../lib/volumevalidate";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { RemoveRowButton } from "@/components/ui/row-editor";
import { SegmentedControl } from "@/components/ui/segmented-control";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

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

const KIND_OPTIONS = [
  { value: "ephemeral" as const, label: "Ephemeral" },
  { value: "new_persistent" as const, label: "New persistent" },
  { value: "existing_persistent" as const, label: "Existing persistent" },
];

/** One editable new-volume row with a 3-way type selector. */
export function VolumeRowEditor({ row, freeVolumes, onChange, onRemove, index }: Props) {
  const n = index + 1;

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
    <div className="flex flex-col gap-2 rounded-lg border border-border p-3">
      {/* Segmented type selector */}
      <SegmentedControl
        value={row.kind}
        onChange={setKind}
        options={KIND_OPTIONS}
        aria-label="Volume type"
      />

      {/* Existing-persistent: dropdown of free named volumes */}
      {isExisting && (
        <div className="flex items-center gap-2">
          <Label className="w-24 shrink-0 text-xs font-semibold text-muted-foreground">
            Volume
          </Label>
          {freeVolumes.length === 0 ? (
            <span className="flex-1 text-xs text-muted-foreground-2">No free volumes available</span>
          ) : (
            <Select
              value={row.selectedVolName}
              onValueChange={(v) => set({ selectedVolName: v })}
            >
              <SelectTrigger className="flex-1" aria-label="existing volume">
                <SelectValue placeholder="Select a volume…" />
              </SelectTrigger>
              <SelectContent>
                {freeVolumes.map((v) => (
                  <SelectItem key={v.name} value={v.name}>
                    {v.name} ({fmtBytes(v.size_bytes)})
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
        </div>
      )}

      {/* New-persistent: free-input name */}
      {showName && (
        <div className="flex items-center gap-2">
          <Label
            htmlFor={`vol-name-${index}`}
            className="w-24 shrink-0 text-xs font-semibold text-muted-foreground"
          >
            Volume name
          </Label>
          <Input
            id={`vol-name-${index}`}
            aria-label={`Volume ${n} name`}
            value={row.name}
            onChange={(e) => set({ name: e.target.value })}
            placeholder="cache"
            className={nameBad ? "border-destructive" : ""}
          />
        </div>
      )}

      {/* Guest path (all kinds) */}
      <div className="flex items-center gap-2">
        <Label
          htmlFor={`vol-path-${index}`}
          className="w-24 shrink-0 text-xs font-semibold text-muted-foreground"
        >
          Guest path
        </Label>
        <Input
          id={`vol-path-${index}`}
          aria-label={`Volume ${n} path`}
          value={row.path}
          onChange={(e) => set({ path: e.target.value })}
          placeholder="/data"
          className={pathBad ? "border-destructive" : ""}
        />
      </div>

      {/* Size: editable for ephemeral/new, read-only display for existing */}
      <div className="flex items-center gap-2">
        {isExisting ? (
          <span className="w-24 shrink-0 text-xs font-semibold text-muted-foreground">Size</span>
        ) : (
          <Label
            htmlFor={`vol-size-${index}`}
            className="w-24 shrink-0 text-xs font-semibold text-muted-foreground"
          >
            Size
          </Label>
        )}
        {isExisting ? (
          <span className="flex-1 font-mono text-sm text-muted-foreground">
            {selectedVol ? fmtBytes(selectedVol.size_bytes) : "—"}
          </span>
        ) : (
          <Input
            id={`vol-size-${index}`}
            aria-label={`Volume ${n} size`}
            value={row.size}
            onChange={(e) => set({ size: e.target.value })}
            placeholder="1g"
            className={`w-24 ${sizeBad ? "border-destructive" : ""}`}
          />
        )}
      </div>

      <div className="flex justify-end">
        <RemoveRowButton
          aria-label={`Remove volume ${n}`}
          onClick={onRemove}
        />
      </div>
    </div>
  );
}
