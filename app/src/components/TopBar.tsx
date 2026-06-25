import type { DaemonStatusView } from "../lib/types";
import type { DaemonPhase } from "../lib/store";
import { Button } from "@/components/ui/button";

export function TopBar({
  phase,
  daemon,
  onAbout,
}: {
  phase: DaemonPhase;
  daemon: DaemonStatusView | null;
  onAbout: () => void;
}) {
  return (
    <header className="flex items-center justify-between px-4 py-2.5 border-b border-border bg-card">
      <div className="flex items-center gap-2 font-semibold">
        <span className="grid place-items-center size-5 rounded-md bg-primary text-primary-foreground text-xs font-extrabold">
          iz
        </span>
        izba
      </div>
      <div className="text-sm text-muted-foreground flex items-center gap-3">
        {phase === "unreachable" ? (
          <span className="flex items-center gap-2">
            <span className="inline-block w-2 h-2 rounded-full bg-destructive" aria-hidden="true" />
            <span className="text-destructive">daemon unreachable</span>
          </span>
        ) : phase === "connecting" ? (
          <span className="flex items-center gap-2">
            <span
              className="inline-block w-2 h-2 rounded-full bg-muted-foreground-2 animate-pulse"
              aria-hidden="true"
            />
            <span>Connecting…</span>
          </span>
        ) : (
          <span className="flex items-center gap-2">
            <span className="inline-block w-2 h-2 rounded-full bg-success" aria-hidden="true" />
            daemon running{daemon ? ` · v${daemon.version}` : ""}
          </span>
        )}
        <Button variant="ghost" size="sm" onClick={onAbout}>
          About
        </Button>
      </div>
    </header>
  );
}
