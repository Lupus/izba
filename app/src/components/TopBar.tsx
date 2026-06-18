import type { DaemonStatusView } from "../lib/types";
import type { DaemonPhase } from "../lib/store";

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
    <header className="flex items-center justify-between px-4 py-2.5 border-b border-line bg-surface">
      <div className="flex items-center gap-2 font-semibold">
        <span className="grid place-items-center w-[22px] h-[22px] rounded-md bg-accent text-white text-xs font-extrabold">
          iz
        </span>
        izba
      </div>
      <div className="text-[13px] text-ink-2 flex items-center gap-3">
        {phase === "unreachable" ? (
          <span className="flex items-center gap-2">
            <span className="inline-block w-2 h-2 rounded-full bg-warn" aria-hidden="true" />
            <span className="text-warn">daemon unreachable</span>
          </span>
        ) : phase === "connecting" ? (
          <span className="flex items-center gap-2">
            <span
              className="inline-block w-2 h-2 rounded-full bg-off animate-pulse"
              aria-hidden="true"
            />
            <span>Connecting…</span>
          </span>
        ) : (
          <span className="flex items-center gap-2">
            <span className="inline-block w-2 h-2 rounded-full bg-ok" aria-hidden="true" />
            daemon running{daemon ? ` · v${daemon.version}` : ""}
          </span>
        )}
        <button className="text-ink-2 hover:text-ink-1" onClick={onAbout}>
          About
        </button>
      </div>
    </header>
  );
}
