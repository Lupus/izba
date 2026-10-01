import { useEffect, useRef, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { api, onLoadProgress } from "../lib/ipc";
import type { ArchiveInfo, ArchiveSandbox, LoadReport } from "../lib/types";
import { ProgressLog } from "./ProgressLog";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";

interface Props {
  /** Names of the sandboxes already on this host (collision check). */
  existing: string[];
  onClose: () => void;
  /** The load finished and the user dismissed the report. */
  onLoaded: (names: string[]) => void;
}

const plural = (n: number) => `${n} sandbox${n === 1 ? "" : "es"}`;

function describe(s: ArchiveSandbox): string {
  const ws = s.workspace_bundled
    ? "workspace included"
    : `workspace not included — expects ${s.source_workspace}`;
  return s.locked ? `${ws} · was locked down on the source machine` : ws;
}

async function browseDir(set: (v: string) => void) {
  const chosen = await open({ directory: true, multiple: false });
  if (typeof chosen === "string") set(chosen);
}

export function LoadArchive({ existing, onClose, onLoaded }: Readonly<Props>) {
  const [path, setPath] = useState("");
  // The listing is only ever the manifest of the CURRENT path: editing the
  // path discards it, so Load can never act on a listing of another file.
  const [info, setInfo] = useState<ArchiveInfo | null>(null);
  const [picked, setPicked] = useState<ReadonlySet<string>>(new Set());
  const [rename, setRename] = useState("");
  const [workspace, setWorkspace] = useState("");
  const [workspaceRoot, setWorkspaceRoot] = useState("");
  const [reading, setReading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState<string[]>([]);
  const [report, setReport] = useState<LoadReport | null>(null);
  // Latest path, readable from a read that resolves after the user moved on.
  const pathRef = useRef("");
  // Id of the newest read: only that one may clear the busy state.
  const readSeq = useRef(0);

  useEffect(() => {
    let unlisten: (() => void) | undefined;
    void onLoadProgress((m) => setProgress((p) => [...p, m])).then((u) => (unlisten = u));
    return () => unlisten?.();
  }, []);

  function changePath(v: string) {
    pathRef.current = v;
    setPath(v);
    setInfo(null);
    setPicked(new Set());
    // Placement typed for one archive must not land on another's sandboxes.
    setRename("");
    setWorkspace("");
    setWorkspaceRoot("");
    setReading(false);
    setError(null);
  }

  async function read(target: string) {
    const seq = ++readSeq.current;
    setReading(true);
    setError(null);
    try {
      const got = await api.archiveInspect(target.trim());
      if (pathRef.current !== target) return;
      setInfo(got);
      setPicked(new Set(got.sandboxes.map((s) => s.name)));
    } catch (e) {
      if (pathRef.current === target) setError(e instanceof Error ? e.message : String(e));
    } finally {
      if (readSeq.current === seq && pathRef.current === target) setReading(false);
    }
  }

  async function browseArchive() {
    const chosen = await open({
      multiple: false,
      filters: [{ name: "izba archive", extensions: ["izba"] }],
    });
    if (typeof chosen === "string") {
      changePath(chosen);
      await read(chosen);
    }
  }

  function toggle(name: string, on: boolean) {
    // "Load as" and the workspace folder describe ONE sandbox; a different
    // selection must not inherit them.
    setRename("");
    setWorkspace("");
    setPicked((prev) => {
      const next = new Set(prev);
      if (on) next.add(name);
      else next.delete(name);
      return next;
    });
  }

  const select = (info?.sandboxes ?? []).filter((s) => picked.has(s.name)).map((s) => s.name);
  const single = select.length === 1;
  const newName = single ? rename.trim() : "";
  // The names the load would create on this host.
  const targets = newName ? [newName] : select;
  const clashes = targets.filter((n) => existing.includes(n));

  async function submit() {
    setBusy(true);
    setError(null);
    setProgress([]);
    const blank = (v: string) => (v.trim() ? v.trim() : null);
    try {
      setReport(
        await api.loadArchive({
          archive: path.trim(),
          select,
          // Single-sandbox options typed for a narrower selection are not sent.
          rename: single ? blank(rename) : null,
          workspace: single ? blank(workspace) : null,
          workspace_root: single ? null : blank(workspaceRoot),
        }),
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const blockers: string[] = [
    ...(info === null ? ["Read the archive to see what it holds."] : []),
    ...(info !== null && select.length === 0 ? ["Select at least one sandbox."] : []),
    ...clashes.map((n) =>
      single
        ? `${n} already exists — load it under a new name.`
        : `${n} already exists — deselect it, or load it alone under a new name.`,
    ),
  ];
  const canLoad = blockers.length === 0 && !busy;

  return (
    <Dialog
      open={true}
      onOpenChange={(o) => {
        // The daemon keeps going whether or not the dialog is open; closing
        // mid-load would hide the warnings and the redo list from the user.
        if (!o && !busy) onClose();
      }}
    >
      <DialogContent className="max-w-lg overflow-y-auto max-h-screen sm:max-h-screen">
        <DialogHeader>
          <DialogTitle>Load sandboxes</DialogTitle>
        </DialogHeader>

        {report ? (
          <>
            <div className="grid gap-2 text-sm">
              <div>Loaded {plural(report.sandboxes.length)}:</div>
              <ul className="grid gap-1">
                {report.sandboxes.map((s) => (
                  <li key={s.name}>
                    <span className="font-semibold">{s.name}</span>{" "}
                    <span className="break-all font-mono text-xs text-muted-foreground">
                      {s.workspace}
                    </span>
                  </li>
                ))}
              </ul>
              {report.warnings.length > 0 && (
                <ul className="list-disc pl-5 text-xs text-muted-foreground">
                  {report.warnings.map((w) => (
                    <li key={w}>{w}</li>
                  ))}
                </ul>
              )}
              {report.redo.length > 0 && (
                <div className="grid gap-1">
                  <span className="text-muted-foreground">To redo on this machine</span>
                  <ul className="list-disc pl-5 text-xs">
                    {report.redo.map((r) => (
                      <li key={r}>{r}</li>
                    ))}
                  </ul>
                </div>
              )}
              <div className="text-xs text-muted-foreground-2">
                Loaded sandboxes arrive stopped — start them when you are ready.
              </div>
            </div>
            <DialogFooter>
              <Button type="button" onClick={() => onLoaded(report.sandboxes.map((s) => s.name))}>
                Done
              </Button>
            </DialogFooter>
          </>
        ) : (
          <>
            <div className="grid gap-3 text-sm">
              <div className="grid gap-1">
                <Label htmlFor="la-path" className="text-muted-foreground">
                  Archive file
                </Label>
                <div className="flex gap-2">
                  <Input
                    id="la-path"
                    aria-label="Archive file"
                    value={path}
                    onChange={(e) => changePath(e.target.value)}
                    className="flex-1"
                  />
                  <Button type="button" variant="secondary" onClick={() => void browseArchive()}>
                    Browse…
                  </Button>
                  <Button
                    type="button"
                    variant="secondary"
                    disabled={path.trim().length === 0 || reading}
                    onClick={() => void read(path)}
                  >
                    Read archive
                  </Button>
                </div>
              </div>

              {info && (
                <div className="grid gap-1">
                  <span className="text-muted-foreground">
                    Sandboxes · saved on {info.source_os} by izba {info.izba_version}
                  </span>
                  {info.sandboxes.map((s) => (
                    <label key={s.name} className="flex items-start gap-2">
                      <Checkbox
                        aria-label={`Load ${s.name}`}
                        checked={picked.has(s.name)}
                        onCheckedChange={(v) => toggle(s.name, v === true)}
                        className="mt-0.5"
                      />
                      <span className="min-w-0">
                        <span className="block truncate">{s.name}</span>
                        <span className="block break-all text-xs text-muted-foreground-2">
                          {describe(s)}
                        </span>
                      </span>
                    </label>
                  ))}
                </div>
              )}

              {info && single && (
                <>
                  <div className="grid gap-1">
                    <Label htmlFor="la-rename" className="text-muted-foreground">
                      Load as
                    </Label>
                    <Input
                      id="la-rename"
                      placeholder={select[0]}
                      value={rename}
                      onChange={(e) => setRename(e.target.value)}
                    />
                  </div>
                  <div className="grid gap-1">
                    <Label htmlFor="la-workspace" className="text-muted-foreground">
                      Workspace folder
                    </Label>
                    <div className="flex gap-2">
                      <Input
                        id="la-workspace"
                        placeholder="Same place as on the source machine"
                        value={workspace}
                        onChange={(e) => setWorkspace(e.target.value)}
                        className="flex-1"
                      />
                      <Button
                        type="button"
                        variant="secondary"
                        aria-label="Browse for workspace folder"
                        onClick={() => void browseDir(setWorkspace)}
                      >
                        Browse…
                      </Button>
                    </div>
                  </div>
                </>
              )}

              {info && select.length > 1 && (
                <div className="grid gap-1">
                  <Label htmlFor="la-root" className="text-muted-foreground">
                    Workspace parent folder
                  </Label>
                  <div className="flex gap-2">
                    <Input
                      id="la-root"
                      placeholder="Same places as on the source machine"
                      value={workspaceRoot}
                      onChange={(e) => setWorkspaceRoot(e.target.value)}
                      className="flex-1"
                    />
                    <Button
                      type="button"
                      variant="secondary"
                      aria-label="Browse for workspace parent folder"
                      onClick={() => void browseDir(setWorkspaceRoot)}
                    >
                      Browse…
                    </Button>
                  </div>
                  <span className="text-xs text-muted-foreground-2">
                    Each workspace goes into its own folder inside this one.
                  </span>
                </div>
              )}
            </div>

            <ProgressLog lines={progress} />
            {error && <div className="mt-3 text-sm text-destructive">{error}</div>}

            <DialogFooter className="gap-2">
              <Button type="button" variant="ghost" disabled={busy} onClick={onClose}>
                Cancel
              </Button>
              <Button
                type="button"
                disabled={!canLoad}
                aria-describedby={blockers.length > 0 ? "la-load-hints" : undefined}
                onClick={() => void submit()}
              >
                {busy ? "Loading…" : "Load"}
              </Button>
            </DialogFooter>
            {blockers.length > 0 && (
              <div id="la-load-hints" className="text-right text-xs text-muted-foreground-2">
                {blockers.map((hint) => (
                  <div key={hint}>{hint}</div>
                ))}
              </div>
            )}
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
