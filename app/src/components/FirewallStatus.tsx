import { useEffect, useState } from "react";
import type { PolicyView } from "../lib/types";
import { api } from "../lib/ipc";

/** A compact badge for the Overview tab: is this sandbox bare (all egress
 *  allowed) or enforcing a firewall, and how many allow rules does it have. */
export function FirewallStatus({ name }: { name: string }) {
  const [policy, setPolicy] = useState<PolicyView | null>(null);

  useEffect(() => {
    let alive = true;
    void (async () => {
      try {
        const p = await api.policyShow(name);
        if (alive) setPolicy(p);
      } catch {
        // Non-critical: the rest of Overview stays usable without the badge.
      }
    })();
    return () => {
      alive = false;
    };
  }, [name]);

  if (!policy) return null;

  if (!policy.enforcing) {
    return (
      <div className="inline-flex w-fit items-center gap-2 rounded-lg border border-line bg-hover px-3 py-1.5 text-sm text-ink-2">
        <span>Firewall off · bare sandbox (all egress allowed)</span>
      </div>
    );
  }

  const n = policy.allow.length;
  return (
    <div className="inline-flex w-fit items-center gap-2 rounded-lg border border-ok/30 bg-ok/5 px-3 py-1.5 text-sm text-ok">
      <span aria-hidden>🛡</span>
      <span>
        Firewall enforcing · {n} allow rule{n === 1 ? "" : "s"}
      </span>
    </div>
  );
}
