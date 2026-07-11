import { useCallback, useEffect, useState } from "react";
import type { DeltaView, DiffView, DriftState } from "../lib/types";
import { api } from "../lib/ipc";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

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

/** Read-only drift view over `izba.yml` vs. the host-managed truth: a banner
 *  keyed on `DriftState`, a per-field delta table, and Export/Promote actions.
 *  Promote only opens the review dialog (built in a follow-up task) — this
 *  component just computes its enablement. */
export function ManifestTab({ name, running }: Readonly<Props>) {
  const [diff, setDiff] = useState<DiffView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [exportedPath, setExportedPath] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const [promoteOpen, setPromoteOpen] = useState(false);

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

  const missingManifest = error !== null && error.includes("izba.yml");
  const canPromote = diff !== null && (diff.state === "repo_ahead" || diff.state === "diverged");
  const canExport = diff !== null && (diff.state === "managed_ahead" || diff.state === "diverged");

  return (
    <div className="flex flex-col gap-4" data-promote-open={promoteOpen} data-running={running}>
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
          onClick={() => setPromoteOpen(true)}
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
    </div>
  );
}
