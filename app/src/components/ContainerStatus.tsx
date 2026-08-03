import { useEffect, useState } from "react";
import { api } from "../lib/ipc";
import { containerLabel } from "../lib/container";

/** One labeled line with the in-guest workload container state, shown on the
 *  Overview tab so GUI users see the same honest story as `izba status`'s
 *  `container:` line — a live VM whose workload has exited reads "stopped
 *  (workload exited)", not a healthy status. Resolution is best-effort like
 *  WorkspacePath: while loading or if `inspect` fails the line simply doesn't
 *  render. A *successful* inspect with no container state renders "unknown". */
export function ContainerStatus({ name }: Readonly<{ name: string }>) {
  // undefined = not loaded (or failed) → no line; string|null = loaded token.
  const [container, setContainer] = useState<string | null | undefined>(undefined);

  useEffect(() => {
    let cancelled = false;
    setContainer(undefined);
    api
      .inspect(name)
      .then((d) => {
        if (!cancelled) setContainer(d.container ?? null);
      })
      .catch(() => {
        /* best-effort: no container line */
      });
    return () => {
      cancelled = true;
    };
  }, [name]);

  if (container === undefined) return null;
  return (
    <div className="text-sm">
      <span className="text-muted-foreground-2">Container </span>
      <span>{containerLabel(container)}</span>
    </div>
  );
}
