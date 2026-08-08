import { meterTone } from "../../lib/format";

const TONE_CLASS: Record<ReturnType<typeof meterTone>, string> = {
  ok: "bg-success",
  warn: "bg-warning",
  crit: "bg-destructive",
};

/** Thin horizontal usage bar. `fraction` may exceed 1 (clamped visually).
 *  Only ever fed TRUSTED host-tier numbers — guest-reported figures stay
 *  secondary text, never a bar (see the design spec's trust model). */
export function Meter({ fraction, label }: Readonly<{ fraction: number; label: string }>) {
  const pct = Math.min(1, Math.max(0, fraction)) * 100;
  return (
    <div
      role="meter"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={Math.round(pct)}
      className="h-1 w-full overflow-hidden rounded-full bg-muted"
    >
      <div
        className={`h-full rounded-full ${TONE_CLASS[meterTone(fraction)]}`}
        style={{ width: `${pct}%` }}
      />
    </div>
  );
}
