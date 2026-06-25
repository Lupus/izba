import type { SbxState } from "../lib/types";

const COLOR: Record<SbxState["kind"], string> = {
  running: "bg-success",
  degraded: "bg-destructive",
  stopped: "bg-muted-foreground-2",
};

export function StatusDot({ state }: { state: SbxState }) {
  const label = state.kind === "degraded" ? `degraded: ${state.reason}` : state.kind;
  return (
    <span
      role="img"
      aria-label={label}
      title={label}
      className={`inline-block w-2 h-2 rounded-full ${COLOR[state.kind]}`}
    />
  );
}
