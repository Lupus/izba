import { useEffect, useState } from "react";
import { save } from "@tauri-apps/plugin-dialog";
import { api, onSaveProgress } from "../lib/ipc";
import { formatBytes } from "../lib/format";
import type { SandboxView, SaveReport } from "../lib/types";
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
  sandboxes: SandboxView[];
  /** Sandbox to preselect (the one open in the detail pane), if any. */
  initial: string | null;
  onClose: () => void;
  /** The save finished and the user dismissed the report. */
  onSaved: () => void;
}

const plural = (n: number) => `${n} sandbox${n === 1 ? "" : "es"}`;

export function SaveArchive({ sandboxes, initial, onClose, onSaved }: Readonly<Props>) {
  const [picked, setPicked] = useState<ReadonlySet<string>>(
    () => new Set(initial && sandboxes.some((s) => s.name === initial) ? [initial] : []),
  );
  const [withWorkspace, setWithWorkspace] = useState(false);
  const [stop, setStop] = useState(false);
  const [out, setOut] = useState("");
  // The one path the native save dialog returned: the OS already asked the
  // user about replacing it, so only THAT exact path may be overwritten.
  const [confirmedOut, setConfirmedOut] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState<string[]>([]);
  const [report, setReport] = useState<SaveReport | null>(null);

  useEffect(() => {
    let unlisten: (() => void) | undefined;
    void onSaveProgress((m) => setProgress((p) => [...p, m])).then((u) => (unlisten = u));
    return () => unlisten?.();
  }, []);

  // Selection in list order, restricted to sandboxes that still exist.
  const names = sandboxes.filter((s) => picked.has(s.name)).map((s) => s.name);
  const running = sandboxes
    .filter((s) => picked.has(s.name) && s.state.kind !== "stopped")
    .map((s) => s.name);

  function toggle(name: string, on: boolean) {
    // Consent to stop was given for the selection as it stood; a different
    // selection may stop a different sandbox, so it has to be given again.
    setStop(false);
    setPicked((prev) => {
      const next = new Set(prev);
      if (on) next.add(name);
      else next.delete(name);
      return next;
    });
  }

  async function browse() {
    const chosen = await save({
      defaultPath: `${names.length === 1 ? names[0] : "sandboxes"}.izba`,
      filters: [{ name: "izba archive", extensions: ["izba"] }],
    });
    if (typeof chosen === "string") {
      setOut(chosen);
      setConfirmedOut(chosen);
    }
  }

  async function submit() {
    setBusy(true);
    setError(null);
    setProgress([]);
    try {
      setReport(
        await api.saveArchive({
          names,
          out: out.trim(),
          with_workspace: withWorkspace,
          // Consent given for an earlier selection must not stop anything now.
          stop: running.length > 0 && stop,
          overwrite: confirmedOut !== null && out === confirmedOut,
        }),
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const blockers: string[] = [
    ...(names.length === 0 ? ["Select at least one sandbox."] : []),
    ...(out.trim().length === 0 ? ["Choose where to save the archive."] : []),
    ...(running.length > 0 && !stop
      ? [
          `${running.join(", ")} ${running.length === 1 ? "is" : "are"} running — a sandbox must be stopped to be saved.`,
        ]
      : []),
  ];
  const canSave = blockers.length === 0 && !busy;

  return (
    <Dialog
      open={true}
      onOpenChange={(open) => {
        // The daemon keeps going whether or not the dialog is open; closing
        // mid-save would only hide the outcome (and any warnings) from the user.
        if (!open && !busy) onClose();
      }}
    >
      <DialogContent className="max-w-lg overflow-y-auto max-h-screen sm:max-h-screen">
        <DialogHeader>
          <DialogTitle>Save sandboxes</DialogTitle>
        </DialogHeader>

        {report ? (
          <>
            <div className="grid gap-2 text-sm">
              <div>
                Saved {plural(report.sandboxes.length)} to{" "}
                <span className="break-all font-mono text-xs">{report.path}</span>
              </div>
              <div className="text-xs text-muted-foreground-2">
                {formatBytes(report.archive_bytes)} archive · {formatBytes(report.logical_bytes)} of
                disk data
              </div>
              {report.warnings.length > 0 && (
                <ul className="list-disc pl-5 text-xs text-muted-foreground">
                  {report.warnings.map((w) => (
                    <li key={w}>{w}</li>
                  ))}
                </ul>
              )}
              <div className="text-xs text-muted-foreground-2">
                Copy the file to the other machine and use Load archive there.
              </div>
            </div>
            <DialogFooter>
              <Button type="button" onClick={onSaved}>
                Done
              </Button>
            </DialogFooter>
          </>
        ) : (
          <>
            <div className="grid gap-3 text-sm">
              <div className="grid gap-1">
                <span className="text-muted-foreground">Sandboxes</span>
                {sandboxes.length === 0 && (
                  <span className="text-xs text-muted-foreground-2">No sandboxes to save.</span>
                )}
                {sandboxes.map((s) => (
                  <label key={s.name} className="flex items-center gap-2">
                    <Checkbox
                      aria-label={`Save ${s.name}`}
                      checked={picked.has(s.name)}
                      onCheckedChange={(v) => toggle(s.name, v === true)}
                    />
                    <span className="truncate">{s.name}</span>
                    <span className="text-xs text-muted-foreground-2">
                      {s.state.kind === "stopped" ? "stopped" : "running"}
                    </span>
                  </label>
                ))}
              </div>
              <div className="grid gap-1">
                <label className="flex items-center gap-2">
                  <Checkbox
                    aria-label="Include workspace folders"
                    checked={withWorkspace}
                    onCheckedChange={(v) => setWithWorkspace(v === true)}
                  />
                  Include workspace folders
                </label>
                <span className="text-xs text-muted-foreground-2">
                  Bundles each sandbox&apos;s project folder so the archive is all the other
                  machine needs.
                </span>
              </div>
              {running.length > 0 && (
                <label className="flex items-center gap-2">
                  <Checkbox
                    aria-label="Stop running sandboxes first"
                    checked={stop}
                    onCheckedChange={(v) => setStop(v === true)}
                  />
                  Stop running sandboxes first
                </label>
              )}
              <div className="grid gap-1">
                <Label htmlFor="sa-out" className="text-muted-foreground">
                  Archive file
                </Label>
                <div className="flex gap-2">
                  <Input
                    id="sa-out"
                    aria-label="Archive file"
                    placeholder="sandboxes.izba"
                    value={out}
                    onChange={(e) => setOut(e.target.value)}
                    className="flex-1"
                  />
                  <Button type="button" variant="secondary" onClick={() => void browse()}>
                    Browse…
                  </Button>
                </div>
              </div>
            </div>

            <ProgressLog lines={progress} />
            {error && <div className="mt-3 text-sm text-destructive">{error}</div>}

            <DialogFooter className="gap-2">
              <Button type="button" variant="ghost" disabled={busy} onClick={onClose}>
                Cancel
              </Button>
              <Button
                type="button"
                disabled={!canSave}
                aria-describedby={blockers.length > 0 ? "sa-save-hints" : undefined}
                onClick={() => void submit()}
              >
                {busy ? "Saving…" : "Save"}
              </Button>
            </DialogFooter>
            {blockers.length > 0 && (
              <div id="sa-save-hints" className="text-right text-xs text-muted-foreground-2">
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
