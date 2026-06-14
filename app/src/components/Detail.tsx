import type { SandboxView } from "../lib/types";
import { StatusDot } from "./StatusDot";

export function Detail({ sandbox }: { sandbox: SandboxView | null }) {
  if (!sandbox) {
    return <div className="flex-1 grid place-items-center text-ink-3">Select a sandbox</div>;
  }
  return (
    <section className="flex-1 p-5">
      <div className="flex items-center gap-3 text-lg font-semibold">
        <StatusDot state={sandbox.state} /> {sandbox.name}
      </div>
      <div className="mt-1 text-ink-2">{sandbox.image}</div>
      {sandbox.state.kind === "degraded" && (
        <div className="mt-3 rounded-lg border border-warn/30 bg-warn/5 px-3 py-2 text-warn text-sm">
          {sandbox.state.reason}
        </div>
      )}
      <div className="mt-4 text-ink-3 text-sm">
        Lifecycle, logs, shell, ports, and firewall tabs arrive in the next milestone.
      </div>
    </section>
  );
}
