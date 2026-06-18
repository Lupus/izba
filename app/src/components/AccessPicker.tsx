import type { Access } from "../lib/types";

/** A two-option segmented control for choosing read vs read-write access. */
export function AccessPicker({
  value,
  onChange,
}: {
  value: Access;
  onChange: (v: Access) => void;
}) {
  const base = "rounded px-2 py-0.5 text-xs font-semibold transition-colors";
  const active = "bg-accent text-white";
  const inactive = "text-ink-2 hover:bg-hover";
  return (
    <span className="inline-flex gap-1 rounded-lg border border-line p-0.5">
      <button
        type="button"
        onClick={() => onChange("read")}
        className={`${base} ${value === "read" ? active : inactive}`}
      >
        read
      </button>
      <button
        type="button"
        onClick={() => onChange("read-write")}
        className={`${base} ${value === "read-write" ? active : inactive}`}
      >
        read-write
      </button>
    </span>
  );
}
