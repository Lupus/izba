import { useCallback, useEffect, useRef, useState } from "react";
import type { Access, EndpointSummary, PolicyView } from "../lib/types";
import { api } from "../lib/ipc";
import { git_repo_from_row, git_op_from_path, git_access_for } from "../lib/git";
import { allowKeys } from "../lib/policy";
import { SeedDialog } from "./SeedDialog";
import { EnforceToggle } from "./EnforceToggle";
import { Button } from "@/components/ui/button";

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

/** What this tab actually KNOWS about the sandbox, from the one `refresh` that
 *  fetches its netlog and its policy together.
 *
 *  `policy` starts `null` and `enforcing` was `policy?.enforcing ?? false`, so
 *  before `policyShow` resolved — and for as long as it kept failing, since
 *  `refresh` is a `Promise.all` and either half rejecting leaves `policy`
 *  untouched — this tab announced "Firewall OFF · all egress currently
 *  allowed" and "0 allow rule(s)" for a sandbox whose policy it had not read,
 *  with the enforce toggle live. `toggleEnforce` computes `next = !enforcing`,
 *  so from that window the write direction is ALWAYS on: it cannot disarm a
 *  firewall, but it can arm a bare sandbox onto an empty allow-list and cut a
 *  running agent's egress — and, worse, it persistently misreports the posture
 *  of an enforcing sandbox, the advertised-posture ≠ enforced-posture class
 *  this project keeps meeting. `FirewallStatus` already renders `…` rather
 *  than characterising this very data; so does this now. */
type LoadState = { kind: "loading" } | { kind: "ready" } | { kind: "error" };

/** Why an enforce toggle was refused, given what we know. Returned as text so
 *  the refusal is VISIBLE (a dropped click teaches the operator nothing) and so
 *  one place decides "may we write a posture?". */
function enforceRefusal(load: LoadState): string | null {
  if (load.kind === "ready") return null;
  const what =
    load.kind === "loading"
      ? "This sandbox's firewall posture has not finished loading"
      : "This sandbox's firewall posture could not be read";
  return `${what}, so the enforce toggle is refused: with no posture to flip, a click here would simply write enforcement ON — arming an unread allow-list, or reporting success for a change that matched nothing. Wait for the policy to load, or use the Policy tab once it does.`;
}

export function NetlogView({ name, pollMs = 1500 }: Readonly<{ name: string; pollMs?: number }>) {
  const [rows, setRows] = useState<EndpointSummary[]>([]);
  const [policy, setPolicy] = useState<PolicyView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loadState, setLoadState] = useState<LoadState>({ kind: "loading" });
  // Kept apart from `error` so a 1.5 s poll landing its own message cannot wipe
  // the reason a write was just refused.
  const [refusal, setRefusal] = useState<string | null>(null);
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

  // The sandbox this tab is currently showing. Every answer is checked against
  // it before it is painted, because an in-flight `refresh` captured the name
  // it was issued for and the selection can move on while it is in flight.
  const shownName = useRef(name);

  const refresh = useCallback(async () => {
    try {
      const [r, p] = await Promise.all([api.readNetlog(name), api.policyShow(name)]);
      // A slow answer for a sandbox the tab has already left describes
      // something that is no longer on screen: painting it would restore
      // exactly the wrong pairing the reset below exists to prevent, and would
      // do it wearing a "ready" posture.
      if (shownName.current !== name) return;
      setRows(r);
      setPolicy(p);
      setError(null);
      setLoadState({ kind: "ready" });
      setRefusal(null);
    } catch (e) {
      if (shownName.current !== name) return;
      const message = e instanceof Error ? e.message : String(e);
      setError(message);
      // Only a load that never succeeded is "unknown". Once a policy has been
      // read, a later poll failing makes it stale, not unread — the rows and
      // the posture on screen are still something izba actually saw.
      setLoadState((prev) => (prev.kind === "ready" ? prev : { kind: "error" }));
    }
  }, [name]);

  useEffect(() => {
    let alive = true;
    // A different sandbox is a different posture, a different allow-list and a
    // different netlog. Reset on the NAME CHANGE, not when the new answer
    // arrives: for that whole window the tab would otherwise pair the new
    // sandbox's name with the previous sandbox's `ready` posture and keep every
    // control live — and `toggleEnforce` would then write
    // `policySetEnforce(NEW, !OLD_POSTURE)`, which unlike the never-loaded
    // window can write OFF and DISARM a firewall. Going back to `loading`
    // hands the whole window to the unknown-posture treatment above, which
    // also withdraws the row-policy actions (they render only under
    // `enforcing`, derived from `policy`). Same guard as PolicyEditor's
    // name-change reset.
    if (shownName.current !== name) {
      shownName.current = name;
      setLoadState({ kind: "loading" });
      setPolicy(null);
      setRows([]);
      setError(null);
      setRefusal(null);
    }
    void refresh();
    const id = setInterval(() => {
      if (alive && !hoveringRef.current) void refresh();
    }, pollMs);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [refresh, pollMs, name]);

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
    // THE guard, in the state transition rather than in the control's rendered
    // state: a scripted click, a stale render or a future markup edit must not
    // be able to route around it, and the refusal must be readable.
    const refused = enforceRefusal(loadState);
    if (refused) {
      setRefusal(refused);
      return;
    }
    setRefusal(null);
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
      {error && <div className="mb-2 text-sm text-destructive">{error}</div>}
      {refusal && <div className="mb-2 text-sm text-destructive">{refusal}</div>}

      {/* Banner: always visible — honest about firewall state */}
      <div className="mb-3 flex items-center justify-between rounded-lg border border-border bg-muted px-3 py-2 text-sm">
        <div>
          {loadState.kind !== "ready" ? (
            /* Neither "ON" nor "OFF": izba has not read this sandbox's policy,
               and an unread policy is not an off one. */
            <span>
              <span>🛡 Firewall posture unknown</span>
              <br />
              <span className="text-muted-foreground-2">
                {loadState.kind === "loading"
                  ? "Reading this sandbox's policy and netlog…"
                  : "izba could not read this sandbox's policy (see the error above), so its enforcement posture and allow-list are unknown here — an unread policy is not an off one."}
              </span>
            </span>
          ) : enforcing ? (
            <span>🛡 Firewall ON · {allowRuleCount} allow rule(s)</span>
          ) : (
            <span>
              <span>🛡 Firewall OFF · all egress currently allowed</span>
              <br />
              <span className="text-muted-foreground-2">
                {rows.length} endpoint(s) observed · {blockedCount} were blocked while enforcing
              </span>
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {/* Enforce toggle — a clear on/off switch, not an ambiguous checkbox.
              Only once the posture is known: a switch knob is itself a posture
              claim, and `enforcing` defaults to false. In the unknown window a
              plain button stands in — `aria-disabled`, deliberately NOT natively
              `disabled`, so the click still reaches `toggleEnforce` and gets a
              visible reason instead of being silently swallowed. */}
          {loadState.kind === "ready" ? (
            <EnforceToggle
              enforcing={enforcing}
              disabled={pending !== null}
              onToggle={() => void toggleEnforce()}
            />
          ) : (
            <Button
              variant="secondary"
              size="sm"
              aria-label="Enforce firewall"
              aria-disabled
              onClick={() => void toggleEnforce()}
            >
              Enforce firewall
            </Button>
          )}
          {/* Review observed traffic button (always available) */}
          <Button
            disabled={pending !== null}
            onClick={() => setShowSeed(true)}
          >
            Review observed traffic
          </Button>
        </div>
      </div>

      <div className="min-h-0 flex-1 overflow-auto">
        <table
          className="w-full text-left text-xs"
          onMouseEnter={() => setHover(true)}
          onMouseLeave={() => setHover(false)}
        >
          <thead className="text-muted-foreground">
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
                <tr key={key} className="border-t border-border">
                  <td className="py-1">
                    {isGit ? (
                      <span>{`git → ${gitRepo}`}</span>
                    ) : (
                      target
                    )}
                  </td>
                  <td>{r.port}</td>
                  <td>{r.tier}</td>
                  <td className={r.verdict === "deny" ? "text-destructive" : "text-success"}>
                    {r.allow_count}✓ {r.deny_count}✕
                  </td>
                  <td className="text-muted-foreground-2" title={new Date(r.last_seen_ms).toLocaleString()}>
                    {relTime(r.last_seen_ms, now)}
                  </td>
                  {enforcing && (
                    <td className={
                      isGit
                        ? (gitAccess !== null ? "text-success" : "text-muted-foreground-2")
                        : permitted ? "text-success" : "text-muted-foreground-2"
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
                            <Button
                              aria-label="Allow read"
                              disabled={busy}
                              size="sm"
                              variant={gitAccess === "read" ? "default" : "secondary"}
                              onClick={() =>
                                void act(key, () => api.policyGitAllow(name, gitRepo, false))
                              }
                            >
                              {busy ? "…" : "Allow read"}
                            </Button>
                            <Button
                              aria-label="Allow write"
                              disabled={busy}
                              size="sm"
                              variant={gitAccess === "read-write" ? "default" : "secondary"}
                              onClick={() =>
                                void act(key, () => api.policyGitAllow(name, gitRepo, true))
                              }
                            >
                              {busy ? "…" : "Allow write"}
                            </Button>
                            <Button
                              aria-label="Block"
                              disabled={busy}
                              size="sm"
                              variant="destructive"
                              onClick={() =>
                                void act(key, () => api.policyGitBlock(name, gitRepo))
                              }
                            >
                              {busy ? "…" : "Block"}
                            </Button>
                          </span>
                        ) : (
                          // No rule yet: call-to-action Allow read / Allow write
                          <span className="flex gap-1">
                            <Button
                              aria-label="Allow read"
                              disabled={busy}
                              size="sm"
                              variant="secondary"
                              onClick={() =>
                                void act(key, () => api.policyGitAllow(name, gitRepo, false))
                              }
                            >
                              {busy ? "…" : "Allow read"}
                            </Button>
                            <Button
                              aria-label="Allow write"
                              disabled={busy}
                              size="sm"
                              variant="secondary"
                              onClick={() =>
                                void act(key, () => api.policyGitAllow(name, gitRepo, true))
                              }
                            >
                              {busy ? "…" : "Allow write"}
                            </Button>
                          </span>
                        )
                      ) : permitted ? (
                        <Button
                          aria-label={`Block ${target}`}
                          disabled={busy}
                          size="sm"
                          variant="destructive"
                          onClick={() =>
                            r.host && void act(key, () => api.policyBlock(name, r.host!, r.port))
                          }
                        >
                          {busy ? "…" : "Block"}
                        </Button>
                      ) : (
                        <Button
                          aria-label={`Allow ${target}`}
                          disabled={rawIp || busy}
                          size="sm"
                          variant="secondary"
                          title={
                            rawIp
                              ? "no resolved name; allowing a bare IP would defeat the SSRF / DNS-rebind guard"
                              : undefined
                          }
                          onClick={() =>
                            r.host && void act(key, () => api.policyAllow(name, r.host!, r.port))
                          }
                        >
                          {busy ? "…" : "Allow"}
                        </Button>
                      )}
                    </td>
                  )}
                </tr>
              );
            })}
          </tbody>
        </table>
        {loadState.kind === "ready" && rows.length === 0 && (
          <div className="mt-3 text-muted-foreground-2">No egress recorded yet.</div>
        )}
      </div>
      {/* Fixed-height status line, always present so toggling its text never
          reflows the table (it sits below the scroll area, not above it). */}
      <div className="mt-2 h-5 shrink-0 text-xs text-muted-foreground-2" aria-live="polite">
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
