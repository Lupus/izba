import type { SandboxStats } from "../../lib/types";
import { formatBytes } from "../../lib/format";
import { OverviewCard, Quiet } from "./CardShell";

/** How many rows the card will ever draw, regardless of what the guest sends. */
const MAX_ROWS = 10;

/** The guest's mini-top. Everything here is GUEST-REPORTED (and daemon-
 *  sanitized): the caption says so, and the card never draws a bar off it.
 *  React escaping plus the daemon's sanitizer make a hostile `comm` inert. */
export function ProcessesCard({ stats }: Readonly<{ stats: SandboxStats | null }>) {
  const body = () => {
    if (stats === null) return <Quiet>…</Quiet>;
    if (!stats.running) return <Quiet>not running</Quiet>;
    if (!stats.guest) return <Quiet>guest not responding</Quiet>;
    const guest = stats.guest;
    return (
      <>
        <table className="w-full font-mono text-xs">
          <thead>
            <tr className="text-left text-muted-foreground-2">
              <th className="pb-1 font-normal">PID</th>
              <th className="pb-1 font-normal">NAME</th>
              <th className="pb-1 text-right font-normal">CPU %</th>
              <th className="pb-1 text-right font-normal">MEM</th>
            </tr>
          </thead>
          <tbody>
            {guest.processes.slice(0, MAX_ROWS).map((p) => (
              <tr key={p.pid}>
                <td className="pr-3">{p.pid}</td>
                <td className="truncate pr-3">{p.comm}</td>
                <td className="text-right">{(p.cpu_permille / 10).toFixed(1)}</td>
                <td className="text-right">{formatBytes(p.rss_kb * 1024)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="mt-2 text-xs text-muted-foreground-2">{`${guest.process_count} total`}</div>
      </>
    );
  };

  return (
    <OverviewCard title="Processes" caption="guest-reported">
      {body()}
    </OverviewCard>
  );
}
