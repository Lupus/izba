import { useEffect, useState } from "react";
import type { PolicyView } from "../lib/types";
import { api } from "../lib/ipc";
import { Badge } from "@/components/ui/badge";

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
      <Badge variant="secondary" className="gap-2 rounded-lg px-3 py-1.5 text-sm font-normal">
        Firewall off · bare sandbox (all egress allowed)
      </Badge>
    );
  }

  const n = policy.allow.length;
  return (
    <Badge variant="success" className="gap-2 rounded-lg px-3 py-1.5 text-sm font-normal">
      <span aria-hidden>🛡</span>
      Firewall enforcing · {n} allow rule{n === 1 ? "" : "s"}
    </Badge>
  );
}
