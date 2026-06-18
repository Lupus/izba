import { useEffect, useRef, useState, useCallback } from "react";
import { api } from "./ipc";
import type { SandboxView, DaemonStatusView } from "./types";

/**
 * Daemon connection phase. `connecting` is the initial state and holds until the
 * FIRST poll settles — during it the daemon may still be spawning under
 * `connect_spawning_izba`, so we must not claim it is running yet. After that it
 * flips between `ready`/`unreachable` per poll outcome.
 */
export type DaemonPhase = "connecting" | "ready" | "unreachable";

export interface PollState {
  sandboxes: SandboxView[];
  daemon: DaemonStatusView | null;
  error: string | null;
  phase: DaemonPhase;
  refresh: () => void;
}

/** Polls list + daemon_status every `intervalMs` (0 = fetch once, no interval). */
export function usePolling(intervalMs = 2000): PollState {
  const [sandboxes, setSandboxes] = useState<SandboxView[]>([]);
  const [daemon, setDaemon] = useState<DaemonStatusView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [phase, setPhase] = useState<DaemonPhase>("connecting");
  // Guards against setState after unmount when a poll resolves late.
  const aliveRef = useRef(true);

  const tick = useCallback(async () => {
    // No overlap guard: if a tick takes > intervalMs the results race.
    // Acceptable at 2s cadence; add an in-flight flag if latency is a concern.
    try {
      const [sbx, st] = await Promise.all([api.list(), api.daemonStatus()]);
      if (!aliveRef.current) return;
      setSandboxes(sbx);
      setDaemon(st);
      setError(null);
      setPhase("ready");
    } catch (e) {
      if (!aliveRef.current) return;
      setError(e instanceof Error ? e.message : String(e));
      setPhase("unreachable");
    }
  }, []);

  useEffect(() => {
    aliveRef.current = true;
    void tick();
    let id: ReturnType<typeof setInterval> | undefined;
    if (intervalMs > 0) id = setInterval(() => void tick(), intervalMs);
    return () => {
      aliveRef.current = false;
      if (id) clearInterval(id);
    };
  }, [tick, intervalMs]);

  const refresh = useCallback(() => void tick(), [tick]);
  return { sandboxes, daemon, error, phase, refresh };
}
