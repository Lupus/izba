import { useEffect, useState } from "react";
import { api } from "../lib/ipc";
import { containerLabel } from "../lib/container";

/** One labeled line with the in-guest workload container state, shown on the
 *  Overview tab so GUI users see the same honest story as `izba status`'s
 *  `container:` line — a live VM whose workload has exited reads "stopped
 *  (workload exited)", not a healthy status. The state is re-polled while
 *  mounted (the workload can exit — and the sandbox stop or restart — without
 *  `name` ever changing), so the line never keeps claiming a stale "running".
 *  Resolution is best-effort like WorkspacePath: while loading or if `inspect`
 *  fails the line doesn't render rather than showing a stale claim. A
 *  *successful* inspect with no container state renders "unknown". */
export function ContainerStatus({ name, pollMs = 3000 }: Readonly<{ name: string; pollMs?: number }>) {
  // undefined = not loaded (or failed) → no line; string|null = loaded token.
  const [container, setContainer] = useState<string | null | undefined>(undefined);

  useEffect(() => {
    let cancelled = false;
    setContainer(undefined);
    const tick = async () => {
      try {
        const d = await api.inspect(name);
        if (!cancelled) setContainer(d.container ?? null);
      } catch {
        // Hide the line instead of keeping a stale (possibly healthy) claim.
        if (!cancelled) setContainer(undefined);
      }
    };
    void tick();
    const id = setInterval(() => void tick(), pollMs);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [name, pollMs]);

  if (container === undefined) return null;
  return (
    <div className="text-sm">
      <span className="text-muted-foreground-2">Container </span>
      <span>{containerLabel(container)}</span>
    </div>
  );
}
