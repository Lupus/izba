import { useEffect, useState } from "react";
import type { VolumeInfo } from "../lib/types";
import { api } from "../lib/ipc";
import { ConfirmDialog } from "./ConfirmDialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { formatBytes } from "../lib/format";

type Confirm =
  | { kind: "delete"; name: string }
  | { kind: "prune" };

/** What this view actually KNOWS about the host's named volumes.
 *
 *  The three states are not interchangeable, and conflating the first two with
 *  a loaded-and-empty list is what let this rail take consent for an
 *  IRREVERSIBLE deletion against a blank screen: before `volumeList` resolved —
 *  and again when it REJECTED, since the empty-state line carried no `!error`
 *  guard — it stated "No named volumes." while `Prune unused` stayed live.
 *  `volume_prune` then deletes every named volume image not referenced by any
 *  sandbox, and those images under `<data>/volumes/` are not recoverable. The
 *  scope is computed daemon-side, so the fiction is never written back; what is
 *  wrong is the CONSENT, taken against a list izba had not read, and which the
 *  confirmation cannot correct because it names no volume. */
type LoadState = { kind: "loading" } | { kind: "ready" } | { kind: "error"; message: string };

/** Why a prune was refused, given what we know. Returned as text so the refusal
 *  is VISIBLE — a silently-dropped click teaches the operator nothing — and so
 *  there is exactly one place that decides "may we delete?". */
function pruneRefusal(load: LoadState): string | null {
  if (load.kind === "ready") return null;
  const what =
    load.kind === "loading"
      ? "The named-volume list has not finished loading"
      : "The named-volume list could not be read";
  return `${what}, so pruning is refused: it would permanently delete every named volume image not referenced by a sandbox, and volume images cannot be recovered. Nothing shown here is a list of what would go. Wait for the list to load, or reopen this view to retry.`;
}

export function StorageView() {
  const [volumes, setVolumes] = useState<VolumeInfo[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<Confirm | null>(null);
  const [listState, setListState] = useState<LoadState>({ kind: "loading" });
  const [pruneResult, setPruneResult] = useState<{ removed: string[]; reclaimed_bytes: number } | null>(null);

  async function load() {
    try {
      const list = await api.volumeList();
      setVolumes(list);
      setListState({ kind: "ready" });
    } catch (e) {
      // Back to "unknown", never to "empty": a list we failed to re-read is not
      // a list that became empty, and Prune must not be offered against it.
      setVolumes([]);
      setListState({ kind: "error", message: e instanceof Error ? e.message : String(e) });
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function handleConfirm() {
    if (!confirm) return;
    if (confirm.kind === "delete") {
      try {
        await api.volumeRemove(confirm.name);
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      }
      setConfirm(null);
      await load();
    } else {
      try {
        const result = await api.volumePrune();
        setPruneResult(result);
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      }
      setConfirm(null);
      await load();
    }
  }

  /** THE prune guard, and the only path that can open the prune confirmation.
   *  It lives in the state transition rather than in the button's rendered
   *  state — the same reasoning that put the PolicyEditor save guard in
   *  `save()`: a scripted click, a stale render or a future markup edit must
   *  not be able to route around it. `handleConfirm` deliberately carries no
   *  second copy: `confirm` is only ever set here and on a `volumes` row (rows
   *  exist only once the list loaded), so a duplicate check there would be an
   *  unreachable rule with no test behind it. The reachable half is asserted
   *  by "refuses to prune while the volume list is still loading". */
  function requestPrune() {
    const refusal = pruneRefusal(listState);
    if (refusal) {
      setError(refusal);
      return;
    }
    setError(null);
    setConfirm({ kind: "prune" });
  }

  function handleCancel() {
    setConfirm(null);
  }

  return (
    <div className="flex h-full flex-col gap-4 p-6 overflow-auto">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Named Volumes</h2>
        {/* `aria-disabled`, deliberately NOT the native `disabled` attribute:
            the click must still reach `requestPrune`, which is where the
            refusal lives and where it produces a VISIBLE reason. A natively
            disabled button swallows the click, explains nothing, and makes any
            test of the guard vacuous. */}
        <Button
          variant="secondary"
          size="sm"
          aria-disabled={listState.kind !== "ready"}
          onClick={requestPrune}
        >
          Prune unused
        </Button>
      </div>

      {listState.kind === "error" && (
        <div className="text-sm text-destructive">
          Could not read the named volumes: {listState.message}. What exists on disk is unknown — an
          errored list is not an empty one. Reopen this view to retry.
        </div>
      )}

      {error && <div className="text-sm text-destructive">{error}</div>}

      {pruneResult && (
        <Card>
          <CardContent className="p-3 text-sm">
            Pruned {pruneResult.removed.length} volume(s) — reclaimed{" "}
            <strong>{formatBytes(pruneResult.reclaimed_bytes)}</strong>
          </CardContent>
        </Card>
      )}

      <p className="text-sm text-muted-foreground-2">
        Persistent volumes are created when you attach a new persistent volume from a sandbox&apos;s{" "}
        <span className="font-medium text-muted-foreground">Volumes</span> tab.
      </p>

      {listState.kind !== "ready" ? (
        /* Distinct from a loaded-and-empty list on purpose: "No named volumes."
           is an inventory claim, and it is the claim the operator prunes
           against. */
        <div className="text-sm text-muted-foreground-2">
          {listState.kind === "loading"
            ? "Reading the named volumes…"
            : "The named volumes are unknown."}
        </div>
      ) : volumes.length === 0 ? (
        <div className="text-sm text-muted-foreground-2">No named volumes.</div>
      ) : (
        <Card>
          <CardContent className="p-0">
            <table className="w-full text-sm border-collapse">
              <thead>
                <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-muted-foreground-2">
                  <th className="pb-2 pr-4 pt-3 pl-4 font-semibold">Name</th>
                  <th className="pb-2 pr-4 pt-3 font-semibold">Size</th>
                  <th className="pb-2 pr-4 pt-3 font-semibold">In use by</th>
                  <th className="pb-2 pt-3 pr-4 font-semibold"></th>
                </tr>
              </thead>
              <tbody>
                {volumes.map((v) => {
                  const inUse = v.referenced_by.length > 0;
                  return (
                    <tr key={v.name} className="border-b border-border/50 hover:bg-muted/30">
                      <td className="py-2 pr-4 pl-4 font-mono">{v.name}</td>
                      <td className="py-2 pr-4">{formatBytes(v.size_bytes)}</td>
                      <td className="py-2 pr-4">
                        <div className="flex flex-wrap gap-1">
                          {v.referenced_by.map((ref) => (
                            <Badge key={ref} variant="secondary" className="font-mono">
                              {ref}
                            </Badge>
                          ))}
                        </div>
                      </td>
                      <td className="py-2 pr-4">
                        <Button
                          variant="destructive"
                          size="sm"
                          disabled={inUse}
                          title={inUse ? `in use by ${v.referenced_by.join(", ")}` : undefined}
                          onClick={() => setConfirm({ kind: "delete", name: v.name })}
                        >
                          Delete
                        </Button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </CardContent>
        </Card>
      )}

      {confirm?.kind === "delete" && (
        <ConfirmDialog
          title="Delete volume"
          message={`Permanently delete volume "${confirm.name}"? This cannot be undone.`}
          confirmLabel="Delete"
          danger
          onConfirm={() => void handleConfirm()}
          onCancel={handleCancel}
        />
      )}

      {confirm?.kind === "prune" && (
        <ConfirmDialog
          title="Prune unused volumes"
          message="Remove all named volumes not referenced by any sandbox? This cannot be undone."
          confirmLabel="Prune"
          danger
          onConfirm={() => void handleConfirm()}
          onCancel={handleCancel}
        />
      )}
    </div>
  );
}
