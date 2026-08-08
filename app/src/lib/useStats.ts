import { useEffect, useState } from "react";
import { api } from "./ipc";
import type { SandboxStats } from "./types";

/** Single shared stats poller for the Overview tab. Keeps the last good
 *  snapshot through transient failures (error is surfaced alongside), skips
 *  overlapping ticks so replies never resolve out of order. */
export function useStats(name: string, intervalMs = 3000): {
  stats: SandboxStats | null;
  error: string | null;
} {
  const [stats, setStats] = useState<SandboxStats | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    let inFlight = false;
    setStats(null);
    setError(null);
    const tick = async () => {
      if (inFlight) return;
      inFlight = true;
      try {
        const s = await api.stats(name);
        if (!cancelled) {
          setStats(s);
          setError(null);
        }
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      } finally {
        inFlight = false;
      }
    };
    void tick();
    const id = setInterval(() => void tick(), intervalMs);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [name, intervalMs]);

  return { stats, error };
}
