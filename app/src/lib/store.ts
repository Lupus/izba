import { useEffect, useState, useCallback } from "react";
import { api } from "./ipc";
import type { SandboxView, DaemonStatusView } from "./types";

export interface PollState {
  sandboxes: SandboxView[];
  daemon: DaemonStatusView | null;
  error: string | null;
  refresh: () => void;
}

/** Polls list + daemon_status every `intervalMs` (0 = fetch once, no interval). */
export function usePolling(intervalMs = 2000): PollState {
  const [sandboxes, setSandboxes] = useState<SandboxView[]>([]);
  const [daemon, setDaemon] = useState<DaemonStatusView | null>(null);
  const [error, setError] = useState<string | null>(null);

  const tick = useCallback(async () => {
    try {
      const [sbx, st] = await Promise.all([api.list(), api.daemonStatus()]);
      setSandboxes(sbx);
      setDaemon(st);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    void tick();
    if (intervalMs <= 0) return;
    const id = setInterval(() => void tick(), intervalMs);
    return () => clearInterval(id);
  }, [tick, intervalMs]);

  return { sandboxes, daemon, error, refresh: () => void tick() };
}
