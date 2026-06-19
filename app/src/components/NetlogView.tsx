import { useCallback, useEffect, useRef, useState } from "react";
import type { Access, EndpointSummary, PolicyView } from "../lib/types";
import { api } from "../lib/ipc";
import { git_repo_from_row, git_op_from_path, git_access_for } from "../lib/git";
import { allowKeys } from "../lib/policy";
import { SeedDialog } from "./SeedDialog";
import { EnforceToggle } from "./EnforceToggle";

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
  // Controls the SeedDialog (Review observed traffic).
  const [showSeed, setShowSeed] = useState(false);
  // While the pointer is over the table we freeze auto-refresh so rows don't
  // shift under an in-flight Allow/Block click. A ref (read inside the interval
  // closure) avoids re-arming the timer on every hover.
  const [hovering, setHovering] = useState(false);
  const hoveringRef = useRef(false);
  const setHover = (v: boolean) => {
    hoveringRef.current = v;
    setHovering(v);
  };

  // A 1-second clock so the Last-activity column stays live even while the
  // pointer is parked over the table: hover pauses polling, so the rows freeze,
  // but their relative-time labels must keep ticking. The deterministic order
  // means these clock re-renders never reshuffle the frozen rows.
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);

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
  const blockedCount = rows.filter((r) => r.deny_count > 0).length;
  const allowRuleCount = (policy?.allow.length ?? 0) + (policy?.git.length ?? 0);

  // Optimistic toggle for the enforce switch.
  async function toggleEnforce() {
    const next = !enforcing;
    // Optimistic: update policy locally first, revert on error.
    setPolicy((prev) => (prev ? { ...prev, enforcing: next } : prev));
    try {
      await api.policySetEnforce(name, next);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      // Revert
      setPolicy((prev) => (prev ? { ...prev, enforcing: !next } : prev));
    }
  }

  return (
    <div className="flex h-full flex-col">
      {error && <div className="mb-2 text-sm text-warn">{error}</div>}

      {/* Banner: always visible — honest about firewall state */}
      <div className="mb-3 flex items-center justify-between rounded-lg border border-line bg-hover px-3 py-2 text-sm">
        <div>
          {enforcing ? (
            <span>🛡 Firewall ON · {allowRuleCount} allow rule(s)</span>
          ) : (
            <span>
              <span>🛡 Firewall OFF · all egress currently allowed</span>
              <br />
              <span className="text-ink-3">
                {rows.length} endpoint(s) observed · {blockedCount} were blocked while enforcing
              </span>
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {/* Enforce toggle — a clear on/off switch, not an ambiguous checkbox */}
          <EnforceToggle
            enforcing={enforcing}
            disabled={pending !== null}
            onToggle={() => void toggleEnforce()}
          />
          {/* Review observed traffic button (always available) */}
          <button
            type="button"
            disabled={pending !== null}
            onClick={() => setShowSeed(true)}
            className="rounded-lg bg-accent px-3 py-1.5 font-semibold text-white disabled:opacity-50"
          >
            Review observed traffic
          </button>
        </div>
      </div>

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

              // Git-op detection
              const gitOp = git_op_from_path(r.last_path);
              const gitRepo = gitOp ? git_repo_from_row(r.host, r.last_path) : null;
              const isGit = gitOp !== null && gitRepo !== null;

              // For git rows: look up the active access from policy
              const gitAccess: Access | null = isGit && gitRepo
                ? git_access_for(gitRepo, policy?.git ?? [])
                : null;

              return (
                <tr key={key} className="border-t border-line">
                  <td className="py-1">
                    {isGit ? (
                      <span>{`git → ${gitRepo}`}</span>
                    ) : (
                      target
                    )}
                  </td>
                  <td>{r.port}</td>
                  <td>{r.tier}</td>
                  <td className={r.verdict === "deny" ? "text-warn" : "text-ok"}>
                    {r.allow_count}✓ {r.deny_count}✕
                  </td>
                  <td className="text-ink-3" title={new Date(r.last_seen_ms).toLocaleString()}>
                    {relTime(r.last_seen_ms, now)}
                  </td>
                  {enforcing && (
                    <td className={
                      isGit
                        ? (gitAccess !== null ? "text-ok" : "text-ink-3")
                        : permitted ? "text-ok" : "text-ink-3"
                    }>
                      {isGit
                        ? (gitAccess !== null ? gitAccess : "blocked")
                        : rawIp ? "—" : permitted ? "allowed" : "blocked"
                      }
                    </td>
                  )}
                  {enforcing && (
                    <td>
                      {isGit && gitRepo ? (
                        gitAccess !== null ? (
                          // Rule exists: show highlighted active access + Block
                          <span className="flex gap-1">
                            <button
                              type="button"
                              aria-label="Allow read"
                              disabled={busy}
                              onClick={() =>
                                void act(key, () => api.policyGitAllow(name, gitRepo, false))
                              }
                              className={`rounded border px-2 py-0.5 disabled:opacity-40 ${
                                gitAccess === "read"
                                  ? "border-accent bg-accent/10 text-accent font-semibold"
                                  : "border-line hover:bg-hover"
                              }`}
                            >
                              {busy ? "…" : "Allow read"}
                            </button>
                            <button
                              type="button"
                              aria-label="Allow write"
                              disabled={busy}
                              onClick={() =>
                                void act(key, () => api.policyGitAllow(name, gitRepo, true))
                              }
                              className={`rounded border px-2 py-0.5 disabled:opacity-40 ${
                                gitAccess === "read-write"
                                  ? "border-accent bg-accent/10 text-accent font-semibold"
                                  : "border-line hover:bg-hover"
                              }`}
                            >
                              {busy ? "…" : "Allow write"}
                            </button>
                            <button
                              type="button"
                              aria-label="Block"
                              disabled={busy}
                              onClick={() =>
                                void act(key, () => api.policyGitBlock(name, gitRepo))
                              }
                              className="rounded border border-warn/40 px-2 py-0.5 text-warn hover:bg-warn/5 disabled:opacity-40"
                            >
                              {busy ? "…" : "Block"}
                            </button>
                          </span>
                        ) : (
                          // No rule yet: call-to-action Allow read / Allow write
                          <span className="flex gap-1">
                            <button
                              type="button"
                              aria-label="Allow read"
                              disabled={busy}
                              onClick={() =>
                                void act(key, () => api.policyGitAllow(name, gitRepo, false))
                              }
                              className="rounded border border-line px-2 py-0.5 hover:bg-hover disabled:opacity-40"
                            >
                              {busy ? "…" : "Allow read"}
                            </button>
                            <button
                              type="button"
                              aria-label="Allow write"
                              disabled={busy}
                              onClick={() =>
                                void act(key, () => api.policyGitAllow(name, gitRepo, true))
                              }
                              className="rounded border border-line px-2 py-0.5 hover:bg-hover disabled:opacity-40"
                            >
                              {busy ? "…" : "Allow write"}
                            </button>
                          </span>
                        )
                      ) : permitted ? (
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
      {/* Fixed-height status line, always present so toggling its text never
          reflows the table (it sits below the scroll area, not above it). */}
      <div className="mt-2 h-5 shrink-0 text-xs text-ink-3" aria-live="polite">
        {hovering ? "Auto-refresh paused while hovering." : ""}
      </div>

      {/* SeedDialog: Review observed traffic */}
      {showSeed && policy && (
        <SeedDialog
          name={name}
          rows={rows}
          policy={policy}
          enforcing={enforcing}
          onClose={() => setShowSeed(false)}
          onApplied={() => { setShowSeed(false); void refresh(); }}
        />
      )}
    </div>
  );
}
