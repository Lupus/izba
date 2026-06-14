import type { DaemonStatusView } from "../lib/types";

export function TopBar({ daemon, error }: { daemon: DaemonStatusView | null; error: string | null }) {
  return (
    <header className="flex items-center justify-between px-4 py-2.5 border-b border-line bg-surface">
      <div className="flex items-center gap-2 font-semibold">
        <span className="grid place-items-center w-[22px] h-[22px] rounded-md bg-accent text-white text-xs font-extrabold">
          iz
        </span>
        izba
      </div>
      <div className="text-[13px] text-ink-2 flex items-center gap-2">
        {error ? (
          <span className="text-warn">● daemon unreachable</span>
        ) : (
          <>
            <span className="inline-block w-2 h-2 rounded-full bg-ok" />
            daemon running{daemon ? ` · v${daemon.version}` : ""}
          </>
        )}
      </div>
    </header>
  );
}
