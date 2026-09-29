import { useEffect, useRef, useState } from "react";
import type { SandboxDetail, SandboxView } from "../../lib/types";
import { api } from "../../lib/ipc";
import { useStats } from "../../lib/useStats";
import { SandboxCard } from "./SandboxCard";
import { ResourcesCard } from "./ResourcesCard";
import { StorageCard } from "./StorageCard";
import { ProcessesCard } from "./ProcessesCard";

/** Slow re-fetch of `inspect` while the tab is mounted. `izba lockdown` /
 *  `izba unlock` (and any other CLI) change the posture outside the app, so
 *  without this the lock-down row would present a stale posture as fact. */
const INSPECT_REFRESH_MS = 15_000;

/** The Overview dashboard: four cards over ONE stats poller (plus a single
 *  non-polling `inspect` for workspace, confinement, docker mode and the
 *  lock-down facts, re-fetched when the sandbox name, its state kind, the
 *  lock-down `rev` or the parent's `actionRev` changes, every
 *  `INSPECT_REFRESH_MS`, and on window focus / tab-visible). Each card takes its
 *  data slice as props, so every degraded state is a plain-props case. */
export function OverviewTab({
  sandbox,
  actionRev = 0,
}: Readonly<{
  sandbox: SandboxView;
  /** Bumped by the parent after a successful lifecycle action: forces an
   *  inspect re-fetch even if the state kind never visibly changed. */
  actionRev?: number;
}>) {
  const { stats, error } = useStats(sandbox.name);
  const [detail, setDetail] = useState<SandboxDetail | null>(null);

  // `rev` bumps on a lock-down/unlock; `state.kind` because the restart-required
  // fact flips on start/stop. Only a NAME change blanks the card ("…").
  const [rev, setRev] = useState(0);
  // Bumped by the slow interval and focus/visibility events (external changes).
  const [tick, setTick] = useState(0);
  // The last inspect rejected: the held posture may be stale, so the lock-down
  // row shows "unknown" instead. Reset on a name change.
  const [refreshFailed, setRefreshFailed] = useState(false);
  const lastName = useRef(sandbox.name);
  const stateKind = sandbox.state.kind;

  useEffect(() => {
    let alive = true;
    if (lastName.current !== sandbox.name) {
      lastName.current = sandbox.name;
      setDetail(null);
      setRefreshFailed(false);
    }
    api.inspect(sandbox.name).then(
      (d) => {
        if (!alive) return;
        setDetail(d);
        setRefreshFailed(false);
      },
      () => {
        // Best-effort: the cards render their placeholder rows without it.
        if (alive) setRefreshFailed(true);
      },
    );
    return () => {
      alive = false;
    };
  }, [sandbox.name, stateKind, rev, actionRev, tick]);

  useEffect(() => {
    const bump = () => setTick((t) => t + 1);
    const onVisible = () => {
      if (document.visibilityState === "visible") bump();
    };
    const id = setInterval(bump, INSPECT_REFRESH_MS);
    window.addEventListener("focus", bump);
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      clearInterval(id);
      window.removeEventListener("focus", bump);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, []);

  return (
    // `overflow-auto`: the tab body is a fixed-height flex child, and four
    // cards + a ten-row process table can outgrow a short window.
    <div className="grid gap-4 overflow-auto md:grid-cols-2">
      {/* The poller keeps its last good snapshot through a failure, so the
          user MUST be told the numbers may no longer be true — a silent stale
          "running · 2h 14m" is exactly the false-health claim the rest of the
          product refuses to make. SandboxCard degrades its live readings too. */}
      {error !== null && (
        <div
          role="status"
          title={error}
          className="rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive md:col-span-2"
        >
          stats unavailable — last update may be stale
        </div>
      )}
      <SandboxCard
        name={sandbox.name}
        state={sandbox.state}
        detail={detail && detail.name === sandbox.name ? detail : null}
        stats={stats}
        stale={error !== null}
        lockdownUnknown={refreshFailed}
        onChanged={() => setRev((r) => r + 1)}
      />
      <ResourcesCard stats={stats} />
      <div className="md:col-span-2">
        <StorageCard stats={stats} />
      </div>
      <div className="md:col-span-2">
        <ProcessesCard stats={stats} />
      </div>
    </div>
  );
}
