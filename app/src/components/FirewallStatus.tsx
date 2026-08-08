import { useEffect, useState } from "react";
import type { PolicyView } from "../lib/types";
import { api } from "../lib/ipc";
import { Badge } from "@/components/ui/badge";

/** A compact badge for the Overview tab: is this sandbox bare (all egress
 *  allowed) or enforcing a firewall, and how many allow rules does it have.
 *
 *  `compact` renders it as a value inside the Sandbox card's labeled-row
 *  rhythm: no "Firewall" prefix (the row label says it), small badge, and an
 *  explicit "…" while the policy is still unknown — an empty labeled row
 *  would read as broken, whereas standalone the badge simply stays away. */
export function FirewallStatus({ name, compact = false }: Readonly<{ name: string; compact?: boolean }>) {
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

  if (!policy) return compact ? <span className="text-muted-foreground-2">…</span> : null;

  if (compact) {
    const n = policy.allow.length;
    return (
      <Badge
        variant={policy.enforcing ? "success" : "secondary"}
        className="px-2 py-0 text-xs font-normal"
      >
        {policy.enforcing ? `enforcing · ${n} allow rule${n === 1 ? "" : "s"}` : "off · all egress allowed"}
      </Badge>
    );
  }

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
