import type { SandboxDetail, SandboxStats, SbxState } from "../../lib/types";
import { containerLabel } from "../../lib/container";
import { formatUptime } from "../../lib/format";
import { StatusDot } from "../StatusDot";
import { FirewallStatus } from "../FirewallStatus";
import { OverviewCard, Row } from "./CardShell";

/** A dot in the same vocabulary as `StatusDot`, for facts that aren't a
 *  sandbox state (the nested docker engine). `aria-hidden` on purpose: the
 *  text beside it carries the meaning, so a screen reader hears it once. */
function Dot({ tone }: Readonly<{ tone: "success" | "destructive" | "muted" }>) {
  const cls = {
    success: "bg-success",
    destructive: "bg-destructive",
    muted: "bg-muted-foreground-2",
  }[tone];
  return <span aria-hidden className={`inline-block h-2 w-2 rounded-full ${cls}`} />;
}

/** Tri-state reading of the nested docker engine, straight off the guest tier:
 *  no guest answer at all ⇒ "unknown" (never a healthy claim), engine down ⇒
 *  destructive + the log tail as secondary text. */
function dockerRow(stats: SandboxStats | null): { tone: "success" | "destructive" | "muted"; text: string; detail: string | null } {
  const engine = stats?.guest?.docker ?? null;
  if (!engine) return { tone: "muted", text: "engine unknown", detail: null };
  if (engine.running) return { tone: "success", text: "engine running", detail: null };
  return { tone: "destructive", text: "engine not running — see logs", detail: engine.detail };
}

/** The identity card: what this sandbox is and how it is contained. Host-side
 *  facts (state, uptime, confinement, workspace, firewall) plus the one
 *  guest-reported line the user already knows from `izba status` — the
 *  workload container state. */
export function SandboxCard({
  name,
  state,
  detail,
  stats,
}: Readonly<{
  name: string;
  state: SbxState;
  detail: SandboxDetail | null;
  stats: SandboxStats | null;
}>) {
  const uptime = stats?.uptime_ms != null ? ` · ${formatUptime(stats.uptime_ms)}` : "";
  const docker = dockerRow(stats);
  const workspace = detail?.workspace ?? "";

  return (
    <OverviewCard title="Sandbox">
      <Row label="state">
        <span className="inline-flex items-center gap-1.5">
          <StatusDot state={state} />
          {state.kind + uptime}
        </span>
      </Row>

      {stats?.running && <Row label="container">{containerLabel(stats.guest?.container ?? null)}</Row>}

      <Row label="confinement">{detail === null ? "…" : (detail.confinement ?? "unknown")}</Row>

      {detail?.docker && (
        <Row label="docker">
          <span className="inline-flex items-center gap-1.5">
            <Dot tone={docker.tone} />
            {docker.text}
          </span>
        </Row>
      )}
      {detail?.docker && docker.detail && (
        <div className="truncate text-right text-xs text-muted-foreground-2" title={docker.detail}>
          {docker.detail}
        </div>
      )}

      <Row label="workspace">
        <span className="block truncate font-mono" title={workspace}>
          {workspace || "…"}
        </span>
      </Row>

      <div className="pt-2">
        <FirewallStatus name={name} />
      </div>
    </OverviewCard>
  );
}
