import type { SandboxStats } from "../../lib/types";
import { formatBytes } from "../../lib/format";
import { OverviewCard, Quiet } from "./CardShell";

interface Segment {
  key: string;
  label: string;
  bytes: number;
  /** Bar/legend swatch color, from the existing token set. */
  cls: string;
  /** Optional trailing note, e.g. docker fullness from the guest's statfs. */
  note: string | null;
}

/** Guest-reported fullness of the docker volume's mount, as a share of the
 *  HOST-measured allocation: "(21% of 10.0 GiB)". Absent whenever the guest
 *  didn't answer or doesn't report that mount. */
function dockerNote(stats: SandboxStats, guestPath: string, dockerBytes: number): string | null {
  const mount = stats.guest?.mounts.find((m) => m.path === guestPath);
  if (!mount || mount.total_bytes <= 0) return null;
  return `(${Math.round((dockerBytes / mount.total_bytes) * 100)}% of ${formatBytes(mount.total_bytes)})`;
}

/** On-disk footprint of this sandbox on the HOST. The headline deliberately
 *  EXCLUDES the rootfs image: it is shared by every sandbox created from the
 *  same image, so summing it would double-count. It is shown as a trailing
 *  "+ image … (shared)" note instead. Fully live for a stopped sandbox — the
 *  disk tier needs no running VM. */
export function StorageCard({ stats }: Readonly<{ stats: SandboxStats | null }>) {
  if (stats === null) {
    return (
      <OverviewCard title="Storage">
        <Quiet>…</Quiet>
      </OverviewCard>
    );
  }

  const disk = stats.disk;
  const dockerVols = disk.volumes.filter((v) => v.docker);
  const dockerBytes = dockerVols.reduce((a, v) => a + v.allocated_bytes, 0);
  const otherVolBytes = disk.volumes.filter((v) => !v.docker).reduce((a, v) => a + v.allocated_bytes, 0);
  const total = disk.rw_img_bytes + dockerBytes + otherVolBytes + disk.logs_bytes;

  const segments: Segment[] = [
    {
      key: "docker",
      label: "docker",
      bytes: dockerBytes,
      cls: "bg-primary",
      note: dockerVols[0] ? dockerNote(stats, dockerVols[0].guest_path, dockerBytes) : null,
    },
    { key: "rw", label: "writable layer", bytes: disk.rw_img_bytes, cls: "bg-success", note: null },
    { key: "vol", label: "volumes", bytes: otherVolBytes, cls: "bg-muted-foreground-2", note: null },
    // NOT `bg-muted`: that is the bar's own track color, which made the logs
    // segment and its swatch invisible.
    { key: "logs", label: "logs", bytes: disk.logs_bytes, cls: "bg-muted-foreground", note: null },
  ].filter((s) => s.bytes > 0);

  return (
    <OverviewCard title="Storage" caption={`${formatBytes(total)} on host`}>
      {total > 0 && (
        <div aria-hidden className="flex h-2 w-full overflow-hidden rounded-full bg-muted">
          {segments.map((s) => (
            <div key={s.key} className={s.cls} style={{ width: `${(s.bytes / total) * 100}%` }} />
          ))}
        </div>
      )}

      <div className="mt-2 flex flex-wrap gap-x-5 gap-y-1">
        {segments.map((s) => (
          <span key={s.key} className="inline-flex items-baseline gap-1.5">
            <span aria-hidden className={`inline-block h-2 w-2 rounded-sm ${s.cls}`} />
            <span className="text-muted-foreground-2">{s.label}</span>
            <span>{formatBytes(s.bytes)}</span>
            {s.note && <span className="text-muted-foreground-2">{s.note}</span>}
          </span>
        ))}
      </div>

      <div className="mt-1 text-muted-foreground-2">
        {`+ image ${formatBytes(disk.image_bytes)} (shared)`}
      </div>
    </OverviewCard>
  );
}
