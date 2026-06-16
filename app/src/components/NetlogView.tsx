import { useCallback, useEffect, useRef, useState } from "react";
import type { AllowEntry, EndpointSummary, PolicyView } from "../lib/types";
import { api } from "../lib/ipc";

/** Expand the policy allow-list into a set of `host:port` keys. A bare-host
 *  string permits the web defaults (80, 443); a scoped entry permits its
 *  exact ports. Lets the table reflect *current policy*, not just past traffic. */
function allowKeys(allow: AllowEntry[]): Set<string> {
  const s = new Set<string>();
  for (const e of allow) {
    if (typeof e === "string") {
      s.add(`${e}:80`);
      s.add(`${e}:443`);
    } else {
      for (const p of e.ports) s.add(`${e.host}:${p}`);
    }
  }
  return s;
}

/** Human-readable "time since" for the Last-activity column. `now` is injected
 *  so the formatting is pure and unit-testable. */
export function relTime(ms: number, now: number): string {
  const delta = Math.max(0, now - ms);
  if (delta < 1000) return "just now";
  const s = Math.floor(delta / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

/** Stable display order: newest endpoint first, then `host:port` as a
 *  tiebreaker. The backend aggregates through a HashMap, so endpoints sharing a
 *  `last_seen_ms` come back in an arbitrary, poll-to-poll-varying order — the
 *  "rows jumping even when stopped" report. A total order pins them in place. */
function orderRows(rows: EndpointSummary[]): EndpointSummary[] {
  return [...rows].sort(
    (a, b) =>
      b.last_seen_ms - a.last_seen_ms ||
      (a.host ?? a.dest_ip).localeCompare(b.host ?? b.dest_ip) ||
      a.port - b.port,
  );
}

export function NetlogView({ name, pollMs = 1500 }: Readonly<{ name: string; pollMs?: number }>) {
  const [rows, setRows] = useState<EndpointSummary[]>([]);
  const [policy, setPolicy] = useState<PolicyView | null>(null);
  const [error, setError] = useState<string | null>(null);
  // The `host:port` key of the row whose action is in flight (for instant feedback).
  const [pending, setPending] = useState<string | null>(null);
  // While the pointer is over the table we freeze auto-refresh so rows don't
  // shift under an in-flight Allow/Block click. A ref (read inside the interval
  // closure) avoids re-arming the timer on every hover.
  const [hovering, setHovering] = useState(false);
  const hoveringRef = useRef(false);
  const setHover = (v: boolean) => {
    hoveringRef.current = v;
    setHovering(v);
  };

  const refresh = useCallback(async () => {
    try {
      const [r, p] = await Promise.all([api.readNetlog(name), api.policyShow(name)]);
      setRows(r);
      setPolicy(p);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [name]);

  useEffect(() => {
    let alive = true;
    void refresh();
    const id = setInterval(() => {
      if (alive && !hoveringRef.current) void refresh();
    }, pollMs);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [refresh, pollMs]);

  // Run an action, then refresh immediately so the Policy column / button flip
  // right away instead of waiting up to 1.5s for the next poll.
  async function act(key: string, fn: () => Promise<unknown>) {
    setPending(key);
    try {
      await fn();
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setPending(null);
    }
  }

  const enforcing = policy?.enforcing ?? false;
  const allowed = allowKeys(policy?.allow ?? []);
  const ordered = orderRows(rows);
  const now = Date.now();

  return (
    <div className="flex h-full flex-col">
      {error && <div className="mb-2 text-sm text-warn">{error}</div>}
      {!enforcing && (
        <div className="mb-3 flex items-center justify-between rounded-lg border border-line bg-hover px-3 py-2 text-sm">
          <span>
            This sandbox has no firewall · {rows.length} endpoint(s) observed (all allowed)
          </span>
          <button
            type="button"
            disabled={pending !== null}
            onClick={() => void act("enable", () => api.policyEnable(name))}
            className="rounded-lg bg-accent px-3 py-1.5 font-semibold text-white disabled:opacity-50"
          >
            Enable firewall — allow these {rows.length}
          </button>
        </div>
      )}
      {enforcing && hovering && rows.length > 0 && (
        <div className="mb-2 text-xs text-ink-3">Auto-refresh paused while hovering.</div>
      )}
      <div className="min-h-0 flex-1 overflow-auto">
        <table
          className="w-full text-left text-xs"
          onMouseEnter={() => setHover(true)}
          onMouseLeave={() => setHover(false)}
        >
          <thead className="text-ink-2">
            <tr>
              <th className="py-1">Endpoint</th>
              <th>Port</th>
              <th>Tier</th>
              <th>Seen</th>
              <th>Last activity</th>
              {enforcing && <th>Policy</th>}
              {enforcing && <th>Action</th>}
            </tr>
          </thead>
          <tbody className="font-mono">
            {ordered.map((r) => {
              const target = r.host ?? r.dest_ip;
              const rawIp = r.host === null;
              const key = `${target}:${r.port}`;
              const permitted = !rawIp && allowed.has(`${r.host}:${r.port}`);
              const busy = pending === key;
              return (
                <tr key={key} className="border-t border-line">
                  <td className="py-1">{target}</td>
                  <td>{r.port}</td>
                  <td>{r.tier}</td>
                  <td className={r.verdict === "deny" ? "text-warn" : "text-ok"}>
                    {r.allow_count}✓ {r.deny_count}✕
                  </td>
                  <td className="text-ink-3" title={new Date(r.last_seen_ms).toLocaleString()}>
                    {relTime(r.last_seen_ms, now)}
                  </td>
                  {enforcing && (
                    <td className={permitted ? "text-ok" : "text-ink-3"}>
                      {rawIp ? "—" : permitted ? "allowed" : "blocked"}
                    </td>
                  )}
                  {enforcing && (
                    <td>
                      {permitted ? (
                        <button
                          type="button"
                          aria-label={`Block ${target}`}
                          disabled={busy}
                          onClick={() =>
                            r.host && void act(key, () => api.policyBlock(name, r.host!, r.port))
                          }
                          className="rounded border border-warn/40 px-2 py-0.5 text-warn hover:bg-warn/5 disabled:opacity-40"
                        >
                          {busy ? "…" : "Block"}
                        </button>
                      ) : (
                        <button
                          type="button"
                          aria-label={`Allow ${target}`}
                          disabled={rawIp || busy}
                          title={
                            rawIp
                              ? "no resolved name; allowing a bare IP would defeat the SSRF / DNS-rebind guard"
                              : undefined
                          }
                          onClick={() =>
                            r.host && void act(key, () => api.policyAllow(name, r.host!, r.port))
                          }
                          className="rounded border border-line px-2 py-0.5 hover:bg-hover disabled:opacity-40"
                        >
                          {busy ? "…" : "Allow"}
                        </button>
                      )}
                    </td>
                  )}
                </tr>
              );
            })}
          </tbody>
        </table>
        {rows.length === 0 && <div className="mt-3 text-ink-3">No egress recorded yet.</div>}
      </div>
    </div>
  );
}
