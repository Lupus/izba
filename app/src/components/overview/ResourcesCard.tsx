import type { SandboxStats } from "../../lib/types";
import { formatBytes } from "../../lib/format";
import { Meter } from "./Meter";
import { OverviewCard, Quiet } from "./CardShell";

/** CPU + memory. Every BAR is a host-observed (trusted) number: the VMM
 *  process's CPU share against the sandbox's vCPU limit, its RSS against the
 *  configured memory limit. The guest's own view is secondary text — it is
 *  guest-reported and must never be drawn as authority. With no host tier at
 *  all (non-Linux host) there are no bars, only that secondary line. */
export function ResourcesCard({ stats }: Readonly<{ stats: SandboxStats | null }>) {
  if (stats === null) return <OverviewCard title="Resources"><Quiet>…</Quiet></OverviewCard>;
  if (!stats.running) return <OverviewCard title="Resources"><Quiet>not running</Quiet></OverviewCard>;

  const host = stats.host;
  const guest = stats.guest;
  const cpuFrac =
    host?.cpu_permille != null && host.cpus_limit > 0
      ? host.cpu_permille / (host.cpus_limit * 1000)
      : null;
  const memFrac = host && host.mem_limit_mb > 0 ? host.rss_kb / (host.mem_limit_mb * 1024) : null;
  const guestUsedKb = guest ? guest.mem_total_kb - guest.mem_available_kb : null;

  return (
    <OverviewCard title="Resources">
      {cpuFrac !== null && host && (
        <div className="pb-2">
          <div className="flex items-baseline justify-between gap-3">
            <span className="text-muted-foreground-2">CPU</span>
            <span className="flex items-baseline gap-2">
              <span className="text-base font-semibold">{`${Math.round(cpuFrac * 100)}%`}</span>
              <span className="text-muted-foreground-2">{`${host.cpus_limit} vCPU`}</span>
            </span>
          </div>
          <Meter fraction={cpuFrac} label="CPU usage" />
        </div>
      )}

      {memFrac !== null && host && (
        <div className="pb-2">
          <div className="flex items-baseline justify-between gap-3">
            <span className="text-muted-foreground-2">MEM</span>
            <span className="text-base font-semibold">
              {`${formatBytes(host.rss_kb * 1024)} / ${formatBytes(host.mem_limit_mb * 1024 * 1024)}`}
            </span>
          </div>
          <Meter fraction={memFrac} label="MEM usage" />
        </div>
      )}

      {guest && guestUsedKb !== null && (
        <div className="text-muted-foreground-2">
          {`guest: ${formatBytes(guestUsedKb * 1024)} used of ${formatBytes(guest.mem_total_kb * 1024)}`}
        </div>
      )}
      {guest && (
        <div className="text-muted-foreground-2">
          {`load ${(guest.load1_centi / 100).toFixed(2)} · ${guest.process_count} processes`}
        </div>
      )}
      {!host && !guest && <Quiet>no resource data</Quiet>}
    </OverviewCard>
  );
}
