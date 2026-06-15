import { useCallback, useEffect, useState } from "react";
import type { EndpointSummary, PolicyView } from "../lib/types";
import { api } from "../lib/ipc";

export function NetlogView({ name }: { name: string }) {
  const [rows, setRows] = useState<EndpointSummary[]>([]);
  const [policy, setPolicy] = useState<PolicyView | null>(null);
  const [error, setError] = useState<string | null>(null);

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
    const id = setInterval(() => alive && void refresh(), 1500);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [refresh]);

  async function act(fn: () => Promise<unknown>) {
    try {
      await fn();
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  const enforcing = policy?.enforcing ?? false;

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
            onClick={() => void act(() => api.policyEnable(name))}
            className="rounded-lg bg-accent px-3 py-1.5 font-semibold text-white"
          >
            Enable firewall — allow these {rows.length}
          </button>
        </div>
      )}
      <div className="min-h-0 flex-1 overflow-auto">
        <table className="w-full text-left text-xs">
          <thead className="text-ink-2">
            <tr>
              <th className="py-1">Endpoint</th>
              <th>Port</th>
              <th>Verdict</th>
              <th>Allow/Deny</th>
              <th>Tier</th>
              {enforcing && <th>Action</th>}
            </tr>
          </thead>
          <tbody className="font-mono">
            {rows.map((r) => {
              const target = r.host ?? r.dest_ip;
              const rawIp = r.host === null;
              return (
                <tr key={`${target}:${r.port}`} className="border-t border-line">
                  <td className="py-1">{target}</td>
                  <td>{r.port}</td>
                  <td className={r.verdict === "deny" ? "text-warn" : "text-ok"}>{r.verdict}</td>
                  <td>
                    {r.allow_count}/{r.deny_count}
                  </td>
                  <td>{r.tier}</td>
                  {enforcing && (
                    <td>
                      {r.verdict === "allow" ? (
                        <button
                          type="button"
                          aria-label={`Block ${target}`}
                          onClick={() => r.host && void act(() => api.policyBlock(name, r.host!, r.port))}
                          className="rounded border border-warn/40 px-2 py-0.5 text-warn hover:bg-warn/5"
                        >
                          Block
                        </button>
                      ) : (
                        <button
                          type="button"
                          aria-label={`Allow ${target}`}
                          disabled={rawIp}
                          title={rawIp ? "no resolved name; allowing a bare IP would defeat the SSRF / DNS-rebind guard" : undefined}
                          onClick={() => r.host && void act(() => api.policyAllow(name, r.host!, r.port))}
                          className="rounded border border-line px-2 py-0.5 hover:bg-hover disabled:opacity-40"
                        >
                          Allow
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
