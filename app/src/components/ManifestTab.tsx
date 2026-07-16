import { Fragment, useCallback, useEffect, useState } from "react";
import type { DeltaView, DiffView, DriftState, PromoteView } from "../lib/types";
import { api } from "../lib/ipc";
import { diffLines } from "../lib/linediff";
import { WorkspacePath } from "./WorkspacePath";
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
// The core promote gate refuses an image-class change without `restart:true`
// REGARDLESS of run state (crates/izba-core/src/manifest/promote.rs:254) — a
// new image needs the rw scratch overlay reconciled with it. On a STOPPED
// sandbox there is no separate "restart" to opt into, so this checkbox is the
// only control that can satisfy the gate; ticking it calls
// `api.manifestPromote(name, true)` same as the running-state checkbox.
// Label is deliberately NOT "reset"/"reset scratch": the app's promote bridge
// (`manifest_promote_core` in app/src-tauri/src/commands.rs) hardcodes
// `reset_scratch: false` — "scratch is never wiped from the app" — so ticking
// this box starts the sandbox on the new image while KEEPING the existing
// scratch overlay, not resetting it. Verified against promote.rs's stopped
// branch: `restart:true` unconditionally sends `Start` once any restart-class
// field is pending, whether or not the sandbox was previously running.
const RESTART_CHECKBOX_LABEL_STOPPED_IMAGE =
  "Start the sandbox to apply the image change (the scratch disk is kept, not reset)";
const WEAKENS_ACK_LABEL = "I understand this weakens the egress firewall";
const STALE_TOKEN_ERROR =
  "izba.yml changed since you viewed this diff. Refresh and review again.";
const NEVER_REVIEWED_ERROR = "Review the diff first — open this tab's latest state, then Promote.";
const IMAGE_RESTART_REQUIRED_ERROR =
  "This image change needs the checkbox above ticked before Promote can continue.";
const RESTART_CLASS_KINDS: ReadonlySet<DeltaView["class"]> = new Set(["restart", "image"]);

// The core's restart-leg failure errors (izba-core/src/manifest/promote.rs):
// the config write has already committed, only the follow-up Start/Stop
// call failed. Both carry a `run \`izba start <name>\`` / CLI-speak tail
// that would be meaningless in the GUI, so they get their own friendly copy
// instead of falling through to the raw message.
const PROMOTE_START_FAILED_ERROR =
  "Promoted, but the sandbox failed to start on the new configuration. Use Start on the sandbox to retry.";
const PROMOTE_STOP_FAILED_ERROR =
  "Promoted, but the sandbox could not be stopped to apply restart-class changes. Stop and Start it manually.";

/** Substring-based mapping of the known promote gate errors to their copy;
 *  anything else passes through as the raw message. The `requires --restart`
 *  case is the image-change gate (promote.rs:254) — with the restart/reset
 *  checkbox now gating the Promote button (see
 *  `RESTART_CHECKBOX_LABEL_STOPPED_IMAGE` above) this should be rare, but the
 *  backend can still be reached in a race (e.g. the diff went stale between
 *  render and click), so this stays belt-and-braces rather than leaking the
 *  raw `--restart`/`--reset-scratch` CLI flags into the GUI. */
function mapPromoteError(message: string): string {
  if (message.includes("izba.yml changed")) return STALE_TOKEN_ERROR;
  if (message.includes("no reviewed diff")) return NEVER_REVIEWED_ERROR;
  if (message.includes("requires --restart")) return IMAGE_RESTART_REQUIRED_ERROR;
  if (message.includes("failed to start sandbox after promote")) return PROMOTE_START_FAILED_ERROR;
  if (message.includes("failed to stop sandbox for restart")) return PROMOTE_STOP_FAILED_ERROR;
  return message;
}

const SCRATCH_KEPT_WARNING =
  "Note: the scratch disk was kept. If the sandbox misbehaves on the new image, recreate it or reset from the CLI.";

/** Same belt-and-braces substring mapping as `mapPromoteError`, but for
 *  `promoteOutcome.warnings` on the SUCCESS path. The app's promote bridge
 *  (`manifest_promote_core` in `app/src-tauri/src/commands.rs`) hardcodes
 *  `reset_scratch: false`, so the core's expert `--reset-scratch=false`
 *  warning (promote.rs's `emit_warn` when `image_changed && !reset_scratch`)
 *  fires on essentially every image-class promote from the GUI — raw
 *  CLI-speak naming a flag with no GUI equivalent. Anything else (e.g. "port
 *  8080 already published") passes through unchanged. */
function mapPromoteWarning(message: string): string {
  if (message.includes("--reset-scratch")) return SCRATCH_KEPT_WARNING;
  return message;
}

/** Side-by-side, line-aligned From/To rendering of one delta's values with
 *  the actual differences highlighted: removed lines tint red on the From
 *  side, added lines green on the To side, common lines stay plain. The
 *  values are multi-line strings (egress policy YAML, one port/volume rule
 *  per line), so `whitespace-pre-wrap` is load-bearing — without it the
 *  newlines collapse into the wall of text the field report showed. Each
 *  visual row is one CSS grid row, so wrapped lines keep the two sides
 *  height-aligned. Index keys are safe: rows are a pure recompute of
 *  (from, to) with no per-row state. */
function ValueDiff({ from, to }: Readonly<{ from: string; to: string }>) {
  const rows = diffLines(from, to);
  return (
    <div className="grid grid-cols-2 gap-x-4 font-mono text-xs leading-5">
      <div className="pb-0.5 font-sans text-muted-foreground-2">From</div>
      <div className="pb-0.5 font-sans text-muted-foreground-2">To</div>
      {rows.map((r, i) => (
        <Fragment key={`${i}-${r.from ?? ""}-${r.to ?? ""}`}>
          <div
            className={
              "whitespace-pre-wrap break-all rounded-sm px-1 " +
              (r.changed && r.from !== null
                ? "bg-destructive/10 text-destructive"
                : "text-muted-foreground")
            }
          >
            {r.from ?? " "}
          </div>
          <div
            className={
              "whitespace-pre-wrap break-all rounded-sm px-1 " +
              (r.changed && r.to !== null ? "bg-success/10 text-success" : "")
            }
          >
            {r.to ?? " "}
          </div>
        </Fragment>
      ))}
    </div>
  );
}

/** The per-field delta list (or its "nothing changed" placeholder), shared by
 *  the tab body and the promote confirm dialog: one block per field — name +
 *  class badge + weakens-egress flag on the header line, then the highlighted
 *  `ValueDiff` under it. Hoisted out of `ManifestTab` (typescript:S3776) so
 *  its conditionals don't add to that component's cognitive complexity. */
function DeltaTable({ deltas }: Readonly<{ deltas: DeltaView[] }>) {
  if (deltas.length === 0) {
    return (
      <div className="text-sm text-muted-foreground-2">
        No field changes between izba.yml and managed settings.
      </div>
    );
  }
  return (
    <div className="flex flex-col text-sm">
      {deltas.map((d) => (
        <div key={d.field} className="border-t border-border py-2">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono">{d.field}</span>
            <Badge variant="secondary" title={CLASS_TOOLTIP[d.class]}>
              {d.class}
            </Badge>
            {d.weakens_egress && <span className="text-destructive">⚠ weakens egress</span>}
          </div>
          <div className="mt-1.5">
            <ValueDiff from={d.from} to={d.to} />
          </div>
        </div>
      ))}
    </div>
  );
}

/** The promote confirm dialog's post-promote summary: what happened
 *  (restarted / stopped-pending / needs-restart) plus any warnings. Hoisted
 *  out of `ManifestTab` (typescript:S3776) so its nested
 *  restarted-vs-stopped ternary and warnings `.map` don't add to that
 *  component's cognitive complexity; behavior/markup is unchanged. */
function PromoteOutcomeSummary({ outcome }: Readonly<{ outcome: PromoteView }>) {
  return (
    <div className="flex flex-col gap-2 text-sm">
      <div className="text-success">Promoted {outcome.applied.length} change(s).</div>
      {outcome.restarted ? (
        <div>Sandbox was started to apply the change.</div>
      ) : (
        outcome.stopped && <div>Sandbox is stopped — changes apply on next start.</div>
      )}
      {outcome.needs_restart && <div>Some changes apply on the next restart.</div>}
      {outcome.warnings.map((w) => (
        <div key={w} className="text-destructive">
          {mapPromoteWarning(w)}
        </div>
      ))}
    </div>
  );
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

  // `keepExportBanner` lets `doExport` below re-fetch the diff after a
  // successful export WITHOUT wiping the "Exported to ..." confirmation it
  // just set — mirroring how `confirmPromote`'s refetch never touches
  // `promoteOutcome`. Every other caller (mount/name-change below, the
  // Refresh button) omits it and gets the pre-fix behavior: a fresh
  // `manifestDiff` clears any stale export confirmation.
  const load = useCallback(
    (keepExportBanner = false) => {
      setError(null);
      if (!keepExportBanner) setExportedPath(null);
      api
        .manifestDiff(name)
        .then((d) => setDiff(d))
        .catch((e: unknown) => {
          setDiff(null);
          setError(e instanceof Error ? e.message : String(e));
        });
    },
    [name],
  );

  useEffect(() => {
    load();
  }, [load]);

  async function doExport() {
    setExporting(true);
    setError(null);
    try {
      const path = await api.manifestExport(name);
      setExportedPath(path);
      // Re-fetch the diff so the banner/digest reflect the just-exported,
      // now-in-sync state — without this, the banner stayed on its
      // pre-export reading (e.g. "Live settings have drifted...") even
      // though the file on disk now matches, and the dogfood truth oracle's
      // last-seen digest (managed_ahead) permanently mismatched the
      // post-export ground truth (in_sync). Mirrors `confirmPromote`, which
      // already refetches after a successful promote. `keepExportBanner`
      // keeps the "Exported to ..." line alive across that refetch.
      load(true);
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
  const missingManifest = error?.includes("no izba.yml found") ?? false;
  const canPromote = diff !== null && (diff.state === "repo_ahead" || diff.state === "diverged");
  // `missingManifest` also enables Export: a workspace with no izba.yml is the
  // BOOTSTRAP case — `izba_core::manifest::ops::export` never reads an existing
  // izba.yml (it writes managed truth, advances base, clears review), so Export
  // is exactly how the file gets created. Without this, the empty-state
  // guidance above says "use Export here" while the button stays permanently
  // disabled (diff is null because manifest_diff errored on the missing file).
  const canExport =
    missingManifest || (diff !== null && (diff.state === "managed_ahead" || diff.state === "diverged"));

  const pendingDeltas = diff?.deltas ?? [];
  const hasNonLiveDelta = pendingDeltas.some((d) => d.class !== "live");
  const hasImageDelta = pendingDeltas.some((d) => d.class === "image");
  // The image-change gate applies REGARDLESS of run state (see
  // RESTART_CHECKBOX_LABEL_STOPPED_IMAGE above), so suppress the generic
  // "apply on next start" note whenever it's in play — that note otherwise
  // contradicts the promote gate, which needs authorization now, not "on the
  // next start" for free.
  const showRestartNote = !hasImageDelta && (hasNonLiveDelta || !running);
  const showRestartCheckbox = running
    ? pendingDeltas.some((d) => RESTART_CLASS_KINDS.has(d.class))
    : hasImageDelta;
  const restartCheckboxLabel = running ? RESTART_CHECKBOX_LABEL : RESTART_CHECKBOX_LABEL_STOPPED_IMAGE;
  const requiresWeakensAck = pendingDeltas.some((d) => d.weakens_egress);
  // Mirrors the weakens-ack gate: an image delta always needs the checkbox
  // ticked (running or stopped — promote.rs:254 doesn't care which), so block
  // the click client-side instead of letting the backend bail with a raw
  // `--restart` CLI error.
  const requiresRestartForImage = hasImageDelta && !restartChecked;
  const confirmDisabled = promoting || (requiresWeakensAck && !weakensAck) || requiresRestartForImage;
  const confirmHint = requiresRestartForImage
    ? "Tick the checkbox above to authorize the image change."
    : undefined;

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

      <WorkspacePath name={name} />

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

          <DeltaTable deltas={diff.deltas} />
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
            <PromoteOutcomeSummary outcome={promoteOutcome} />
          ) : (
            <div className="flex flex-col gap-3 text-sm">
              <div>The following changes will be applied to &apos;{name}&apos;:</div>

              <DeltaTable deltas={pendingDeltas} />

              {showRestartNote && (
                <div className="text-muted-foreground-2">{RESTART_NOTE}</div>
              )}

              {showRestartCheckbox && (
                <label className="flex items-center gap-2 cursor-pointer">
                  <Checkbox
                    checked={restartChecked}
                    onCheckedChange={(v) => setRestartChecked(v === true)}
                    aria-label={restartCheckboxLabel}
                  />
                  {restartCheckboxLabel}
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
                  title={confirmHint}
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
