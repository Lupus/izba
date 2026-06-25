import { useEffect, useState } from "react";
import type { VolumeInfo } from "../lib/types";
import { api } from "../lib/ipc";
import { ConfirmDialog } from "./ConfirmDialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  const i = Math.floor(Math.log2(bytes) / 10);
  const idx = Math.min(i, units.length - 1);
  const val = bytes / Math.pow(1024, idx);
  return `${val % 1 === 0 ? val.toFixed(0) : val.toFixed(1)} ${units[idx]}`;
}

type Confirm =
  | { kind: "delete"; name: string }
  | { kind: "prune" };

export function StorageView() {
  const [volumes, setVolumes] = useState<VolumeInfo[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<Confirm | null>(null);
  const [pruneResult, setPruneResult] = useState<{ removed: string[]; reclaimed_bytes: number } | null>(null);

  async function load() {
    try {
      const list = await api.volumeList();
      setVolumes(list);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
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

  function handleCancel() {
    setConfirm(null);
  }

  return (
    <div className="flex h-full flex-col gap-4 p-6 overflow-auto">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Named Volumes</h2>
        <Button
          variant="secondary"
          size="sm"
          onClick={() => setConfirm({ kind: "prune" })}
        >
          Prune unused
        </Button>
      </div>

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

      {volumes.length === 0 ? (
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
