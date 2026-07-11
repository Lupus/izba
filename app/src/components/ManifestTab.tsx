import { useCallback, useEffect, useState } from "react";
import type { DeltaView, DiffView, DriftState, PromoteView } from "../lib/types";
import { api } from "../lib/ipc";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";

interface Props {
  name: string;
  running: boolean;
}

const BANNER_TEXT: Record<DriftState, string> = {
  in_sync: "In sync — izba.yml and managed settings match.",
  repo_ahead: "izba.yml has changes not yet applied. Review below, then Promote.",
  managed_ahead: "Live settings have drifted from izba.yml. Export to capture them.",
  diverged: "Both izba.yml and managed settings changed. Promote applies izba.yml; Export overwrites it.",
};

const BANNER_CLASS: Record<DriftState, string> = {
  in_sync: "border-success/30 bg-success/5 text-success",
  repo_ahead: "border-primary/30 bg-primary/5 text-foreground",
  managed_ahead: "border-destructive/30 bg-destructive/5 text-destructive",
  diverged: "border-destructive/30 bg-destructive/10 text-destructive",
};

const CLASS_TOOLTIP: Record<DeltaView["class"], string> = {
  live: "applies immediately",
  restart: "applies on next start",
  image: "image change — applies on next start",
};

const NO_PROMOTE_HINT = "Nothing to promote — izba.yml has no unapplied changes.";
const NO_EXPORT_HINT = "Nothing to export — no managed-side drift.";
const MISSING_MANIFEST_HEADING = "No izba.yml found in this sandbox's workspace.";
const MISSING_MANIFEST_BODY =
  "Create an izba.yml in the workspace to manage this sandbox declaratively — the manifest describes image, resources, ports, volumes and firewall policy. Run 'izba export <name>' or use Export here after making changes in the app.";

const RESTART_NOTE = "Changes that need a restart apply on the next start.";
const RESTART_CHECKBOX_LABEL = "Restart now to apply restart-class changes";
const WEAKENS_ACK_LABEL = "I understand this weakens the egress firewall";
const STALE_TOKEN_ERROR =
  "izba.yml changed since you viewed this diff. Refresh and review again.";
const NEVER_REVIEWED_ERROR = "Review the diff first — open this tab's latest state, then Promote.";
const RESTART_CLASS_KINDS: ReadonlySet<DeltaView["class"]> = new Set(["restart", "image"]);

/** Substring-based mapping of the two known promote gate errors to their
 *  copy; anything else passes through as the raw message. */
function mapPromoteError(message: string): string {
  if (message.includes("izba.yml changed")) return STALE_TOKEN_ERROR;
  if (message.includes("no reviewed diff")) return NEVER_REVIEWED_ERROR;
  return message;
}

/** Drift view over `izba.yml` vs. the host-managed truth: a banner keyed on
 *  `DriftState`, a per-field delta table, Export, and a Promote confirm
 *  dialog (weakens-egress acknowledgment, optional restart, outcome/error
 *  rendering) that calls `api.manifestPromote` and always refetches the
 *  diff after a successful promote. */
export function ManifestTab({ name, running }: Readonly<Props>) {
  const [diff, setDiff] = useState<DiffView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [exportedPath, setExportedPath] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const [promoteOpen, setPromoteOpen] = useState(false);
  const [weakensAck, setWeakensAck] = useState(false);
  const [restartChecked, setRestartChecked] = useState(false);
  const [promoting, setPromoting] = useState(false);
  const [promoteError, setPromoteError] = useState<string | null>(null);
  const [promoteOutcome, setPromoteOutcome] = useState<PromoteView | null>(null);

  const load = useCallback(() => {
    setError(null);
    setExportedPath(null);
    api
      .manifestDiff(name)
      .then((d) => setDiff(d))
      .catch((e: unknown) => {
        setDiff(null);
        setError(e instanceof Error ? e.message : String(e));
      });
  }, [name]);

  useEffect(() => {
    load();
  }, [load]);

  async function doExport() {
    setExporting(true);
    setError(null);
    try {
      const path = await api.manifestExport(name);
      setExportedPath(path);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setExporting(false);
    }
  }

  // Keyed on the backend's exact "not found" sentinel (manifest_diff_core in
  // commands.rs), NOT on the mere presence of "izba.yml" in the message — a
  // CORRUPT izba.yml also produces an error mentioning "izba.yml" (a parse
  // failure), and that must render honestly in the raw error area below
  // instead of being told the file doesn't exist.
  const missingManifest = error !== null && error.includes("no izba.yml found");
  const canPromote = diff !== null && (diff.state === "repo_ahead" || diff.state === "diverged");
  const canExport = diff !== null && (diff.state === "managed_ahead" || diff.state === "diverged");

  const pendingDeltas = diff?.deltas ?? [];
  const hasNonLiveDelta = pendingDeltas.some((d) => d.class !== "live");
  const showRestartNote = hasNonLiveDelta || !running;
  const showRestartCheckbox = running && pendingDeltas.some((d) => RESTART_CLASS_KINDS.has(d.class));
  const requiresWeakensAck = pendingDeltas.some((d) => d.weakens_egress);
  const confirmDisabled = promoting || (requiresWeakensAck && !weakensAck);

  function openPromote() {
    setWeakensAck(false);
    setRestartChecked(false);
    setPromoteError(null);
    setPromoteOutcome(null);
    setPromoteOpen(true);
  }

  function closePromote() {
    setPromoteOpen(false);
  }

  async function confirmPromote() {
    setPromoting(true);
    setPromoteError(null);
    try {
      const outcome = await api.manifestPromote(name, restartChecked);
      setPromoteOutcome(outcome);
      load();
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      setPromoteError(mapPromoteError(message));
    } finally {
      setPromoting(false);
    }
  }

  return (
    <div className="flex flex-col gap-4" data-running={running}>
      <div className="flex flex-wrap items-center gap-2">
        <Button type="button" variant="secondary" size="sm" onClick={() => load()}>
          Refresh
        </Button>
        <Button
          type="button"
          variant="secondary"
          size="sm"
          disabled={!canExport || exporting}
          title={canExport ? undefined : NO_EXPORT_HINT}
          onClick={() => void doExport()}
        >
          Export to izba.yml
        </Button>
        <Button
          type="button"
          variant="default"
          size="sm"
          disabled={!canPromote}
          title={canPromote ? undefined : NO_PROMOTE_HINT}
          onClick={() => openPromote()}
        >
          Promote…
        </Button>
      </div>

      {error && !missingManifest && <div className="text-sm text-destructive">{error}</div>}

      {missingManifest && (
        <div className="rounded-lg border border-border bg-muted px-3 py-3 text-sm">
          <div className="font-semibold">{MISSING_MANIFEST_HEADING}</div>
          <div className="mt-1 text-muted-foreground">{MISSING_MANIFEST_BODY}</div>
        </div>
      )}

      {exportedPath && <div className="text-sm text-success">Exported to {exportedPath}</div>}

      {diff && (
        <>
          <div className={`rounded-lg border px-3 py-2 text-sm ${BANNER_CLASS[diff.state]}`}>
            {BANNER_TEXT[diff.state]}
          </div>

          {diff.deltas.length === 0 ? (
            <div className="text-sm text-muted-foreground-2">
              No field changes between izba.yml and managed settings.
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-muted-foreground-2">
                  <th className="pb-1 font-normal">Field</th>
                  <th className="pb-1 font-normal">From</th>
                  <th className="pb-1 font-normal">To</th>
                  <th className="pb-1 font-normal" />
                </tr>
              </thead>
              <tbody>
                {diff.deltas.map((d) => (
                  <tr key={d.field} className="border-t border-border">
                    <td className="py-2 font-mono">{d.field}</td>
                    <td className="py-2 pl-2 font-mono text-muted-foreground">{d.from}</td>
                    <td className="py-2 pl-2 font-mono">{d.to}</td>
                    <td className="py-2 pl-2">
                      <span className="inline-flex items-center gap-2">
                        <Badge variant="secondary" title={CLASS_TOOLTIP[d.class]}>
                          {d.class}
                        </Badge>
                        {d.weakens_egress && <span className="text-destructive">⚠ weakens egress</span>}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}

      <Dialog
        open={promoteOpen}
        onOpenChange={(open) => {
          if (!open) closePromote();
        }}
      >
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Promote izba.yml changes</DialogTitle>
          </DialogHeader>

          {promoteOutcome ? (
            <div className="flex flex-col gap-2 text-sm">
              <div className="text-success">Promoted {promoteOutcome.applied.length} change(s).</div>
              {promoteOutcome.stopped && (
                <div>Sandbox is stopped — changes apply on next start.</div>
              )}
              {promoteOutcome.needs_restart && <div>Some changes apply on the next restart.</div>}
              {promoteOutcome.warnings.map((w) => (
                <div key={w} className="text-destructive">
                  {w}
                </div>
              ))}
            </div>
          ) : (
            <div className="flex flex-col gap-3 text-sm">
              <div>The following changes will be applied to &apos;{name}&apos;:</div>

              <ul className="flex flex-col gap-1">
                {pendingDeltas.map((d) => (
                  <li key={d.field} className="flex items-center gap-2">
                    <span className="font-mono">{d.field}</span>
                    <span className="text-muted-foreground">
                      {d.from} → {d.to}
                    </span>
                    <Badge variant="secondary" title={CLASS_TOOLTIP[d.class]}>
                      {d.class}
                    </Badge>
                    {d.weakens_egress && (
                      <span className="text-destructive">⚠ weakens egress</span>
                    )}
                  </li>
                ))}
              </ul>

              {showRestartNote && (
                <div className="text-muted-foreground-2">{RESTART_NOTE}</div>
              )}

              {showRestartCheckbox && (
                <label className="flex items-center gap-2 cursor-pointer">
                  <Checkbox
                    checked={restartChecked}
                    onCheckedChange={(v) => setRestartChecked(v === true)}
                    aria-label={RESTART_CHECKBOX_LABEL}
                  />
                  {RESTART_CHECKBOX_LABEL}
                </label>
              )}

              {requiresWeakensAck && (
                <label className="flex items-center gap-2 cursor-pointer">
                  <Checkbox
                    checked={weakensAck}
                    onCheckedChange={(v) => setWeakensAck(v === true)}
                    aria-label={WEAKENS_ACK_LABEL}
                  />
                  {WEAKENS_ACK_LABEL}
                </label>
              )}

              {promoteError && <div className="text-destructive">{promoteError}</div>}
            </div>
          )}

          <DialogFooter className="gap-2">
            {promoteOutcome ? (
              <Button type="button" variant="secondary" onClick={() => closePromote()}>
                Close
              </Button>
            ) : (
              <>
                <Button type="button" variant="ghost" onClick={() => closePromote()}>
                  Cancel
                </Button>
                <Button
                  type="button"
                  variant="default"
                  disabled={confirmDisabled}
                  onClick={() => void confirmPromote()}
                >
                  Promote
                </Button>
              </>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
