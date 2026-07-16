import { useEffect, useState } from "react";
import { api } from "../lib/ipc";

/** One labeled line with the sandbox's host workspace directory, shown on the
 *  Overview and Manifest tabs so the user can locate the workspace (and its
 *  `izba.yml`) without dropping to the CLI. `select-all` makes the path
 *  copyable in one click. Resolution is best-effort: while loading or if
 *  `inspect` fails (e.g. the daemon is restarting) the line simply doesn't
 *  render — the tabs stay usable and nothing overwrites their own errors. */
export function WorkspacePath({ name }: Readonly<{ name: string }>) {
  const [workspace, setWorkspace] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setWorkspace(null);
    api
      .inspect(name)
      .then((d) => {
        if (!cancelled) setWorkspace(d.workspace || null);
      })
      .catch(() => {
        /* best-effort: no workspace line */
      });
    return () => {
      cancelled = true;
    };
  }, [name]);

  if (!workspace) return null;
  return (
    <div className="text-sm">
      <span className="text-muted-foreground-2">Workspace </span>
      <span className="select-all break-all font-mono" title={workspace}>
        {workspace}
      </span>
    </div>
  );
}
