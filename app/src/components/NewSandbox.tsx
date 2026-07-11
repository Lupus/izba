import { useEffect, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { api, onCreateProgress } from "../lib/ipc";
import type { CreateOpts, VolumeInfo } from "../lib/types";
import { isValidPort, isValidBind } from "../lib/portvalidate";
import {
  type VolumeRow,
  defaultVolumeRow,
  buildVolSpec,
  freeVolumes as computeFreeVolumes,
  isBlankVolRow,
  isValidVolRow,
  usedExistingNames,
  volNameError,
  volPathError,
  volSizeError,
  volPickError,
} from "../lib/volumevalidate";
import { VolumeRowEditor } from "./VolumeRowEditor";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { EditableList } from "@/components/ui/editable-list";

// NewSandbox has no seeded volumes, so the seeded-names set is always empty —
// hoisted to a module constant to avoid re-allocating an empty Set per render.
const NO_SEEDED: ReadonlySet<string> = new Set();

interface Props {
  onClose: () => void;
  onCreated: (name: string) => void;
}

interface PortRow {
  bind: string;
  host: string;
  guest: string;
}

export function NewSandbox({ onClose, onCreated }: Readonly<Props>) {
  const [name, setName] = useState("");
  const [image, setImage] = useState("ubuntu:24.04");
  const [cpus, setCpus] = useState(2);
  const [memMb, setMemMb] = useState(4096);
  const [rwSizeGb, setRwSizeGb] = useState(8);
  const [workspace, setWorkspace] = useState("");
  const [ports, setPorts] = useState<PortRow[]>([]);
  const [volumeRows, setVolumeRowsState] = useState<VolumeRow[]>([]);
  const [allVolumes, setAllVolumes] = useState<VolumeInfo[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState<string[]>([]);

  useEffect(() => {
    let unlisten: (() => void) | undefined;
    void onCreateProgress((m) => setProgress((p) => [...p, m])).then((u) => (unlisten = u));
    return () => unlisten?.();
  }, []);

  useEffect(() => {
    void (async () => {
      try {
        setAllVolumes(await api.volumeList());
      } catch {
        // Non-fatal: the existing-persistent dropdown simply shows empty.
      }
    })();
  }, []);

  async function pickDir() {
    const picked = await open({ directory: true, multiple: false });
    if (typeof picked === "string") {
      setWorkspace(picked);
      if (!name) {
        const base = picked.split(/[/\\]/).filter(Boolean).pop() ?? "";
        setName(base.toLowerCase().replace(/[^a-z0-9_.-]/g, "-"));
      }
    }
  }

  const setPort = (i: number, patch: Partial<PortRow>) =>
    setPorts((rows) => rows.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  const addPort = () => setPorts((rows) => [...rows, { bind: "", host: "", guest: "" }]);
  const removePort = (i: number) => setPorts((rows) => rows.filter((_, j) => j !== i));

  const addVolume = () => setVolumeRowsState((rows) => [...rows, defaultVolumeRow()]);
  const removeVolume = (i: number) => setVolumeRowsState((rows) => rows.filter((_, j) => j !== i));
  const setVolumeRow = (i: number, row: VolumeRow) =>
    setVolumeRowsState((rows) => rows.map((r, j) => (j === i ? row : r)));

  // Free volumes for each row: exclude referenced + names used in other rows as
  // existing_persistent. NewSandbox has no seeded volumes (NO_SEEDED, module const).
  function freeVolumesFor(rowIdx: number): VolumeInfo[] {
    return computeFreeVolumes(allVolumes, NO_SEEDED, usedExistingNames(volumeRows, rowIdx));
  }

  async function submit() {
    setBusy(true);
    setError(null);
    setProgress([]);
    const opts: CreateOpts = {
      name,
      image,
      cpus,
      mem_mb: memMb,
      workspace,
      rw_size_gb: rwSizeGb,
      ports: ports
        .filter((r) => r.host.trim() && r.guest.trim())
        .map(
          (r) =>
            `${r.bind.trim() ? `${r.bind.trim()}:` : ""}${r.host.trim()}:${r.guest.trim()}`,
        ),
      volumes: volumeRows.filter((r) => !isBlankVolRow(r)).map((r) => buildVolSpec(r, allVolumes)),
    };
    try {
      const created = await api.create(opts);
      onCreated(created);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  // A row the user added but left entirely blank is ignored (so a stray
  // "Add port" click can't block submit). Any row they started filling must
  // carry numeric host AND guest ports in 1–65535, plus a valid IPv4 bind (or
  // empty → the daemon defaults it to 127.0.0.1). The bind contract mirrors
  // izba_core::portfwd::parse_rule, which parses bind as an Ipv4Addr.
  const isBlankRow = (r: PortRow) => !r.bind.trim() && !r.host.trim() && !r.guest.trim();
  const isValidRow = (r: PortRow) =>
    isValidPort(r.host) && isValidPort(r.guest) && isValidBind(r.bind);
  const portsInvalid = ports.some((r) => !isBlankRow(r) && !isValidRow(r));

  const volumesInvalid = volumeRows.some((r) => !isBlankVolRow(r) && !isValidVolRow(r));

  // Every reason Create is disabled, in one list, so the boolean below and the
  // on-screen explanation can never drift apart. `busy` isn't listed here: the
  // button already says "Creating…" while it's true, which is self-explanatory.
  const createBlockers: string[] = [
    ...(name.trim().length === 0 ? ["Name is required."] : []),
    ...(workspace.trim().length === 0 ? ["Workspace folder is required."] : []),
    ...(portsInvalid ? ["Fix the invalid port row above."] : []),
    ...(volumesInvalid ? ["Fix the invalid volume row above."] : []),
  ];

  const canCreate = createBlockers.length === 0 && !busy;

  return (
    <Dialog
      open={true}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <DialogContent className="max-w-lg overflow-y-auto max-h-screen sm:max-h-screen">
        <DialogHeader>
          <DialogTitle>New sandbox</DialogTitle>
        </DialogHeader>

        <div className="grid gap-3 text-sm">
          <div className="grid gap-1">
            <Label htmlFor="ns-name" className="text-muted-foreground">
              Name
            </Label>
            <Input
              id="ns-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>
          <div className="grid gap-1">
            <Label htmlFor="ns-workspace" className="text-muted-foreground">
              Workspace
            </Label>
            <div className="flex gap-2">
              <Input
                id="ns-workspace"
                aria-label="Workspace"
                value={workspace}
                onChange={(e) => setWorkspace(e.target.value)}
                className="flex-1"
              />
              <Button
                type="button"
                variant="secondary"
                onClick={() => void pickDir()}
              >
                Browse…
              </Button>
            </div>
          </div>
          <div className="grid gap-1">
            <Label htmlFor="ns-image" className="text-muted-foreground">
              Image
            </Label>
            <Input
              id="ns-image"
              value={image}
              onChange={(e) => setImage(e.target.value)}
            />
          </div>
          <div className="grid grid-cols-3 gap-3">
            <div className="grid gap-1">
              <Label htmlFor="ns-cpus" className="text-muted-foreground">
                vCPUs
              </Label>
              <Input
                id="ns-cpus"
                type="number"
                min={1}
                value={cpus}
                onChange={(e) => setCpus(+e.target.value)}
              />
            </div>
            <div className="grid gap-1">
              <Label htmlFor="ns-mem" className="text-muted-foreground">
                Memory (MiB)
              </Label>
              <Input
                id="ns-mem"
                type="number"
                min={256}
                value={memMb}
                onChange={(e) => setMemMb(+e.target.value)}
              />
            </div>
            <div className="grid gap-1">
              <Label htmlFor="ns-disk" className="text-muted-foreground">
                Disk (GiB)
              </Label>
              <Input
                id="ns-disk"
                type="number"
                min={1}
                value={rwSizeGb}
                onChange={(e) => setRwSizeGb(+e.target.value)}
              />
            </div>
          </div>
          <div className="grid gap-1">
            <span className="text-muted-foreground">Ports</span>
            {ports.length > 0 && (
              <div className="flex gap-2 text-xs text-muted-foreground-2">
                <span className="flex-1">Bind address</span>
                <span className="w-20">Host port</span>
                <span className="w-3" />
                <span className="w-20">Guest port</span>
                {/* spacer for the remove-button column EditableList appends */}
                <span className="w-8" />
              </div>
            )}
            <EditableList
              density="inline"
              items={ports}
              renderRow={(r, i) => {
                const invalid = !isBlankRow(r) && !isValidRow(r);
                return (
                  <>
                    <Input
                      aria-label={`Port ${i + 1} bind`}
                      placeholder="127.0.0.1"
                      value={r.bind}
                      onChange={(e) => setPort(i, { bind: e.target.value })}
                      className={`flex-1${invalid && !isValidBind(r.bind) ? " border-destructive" : ""}`}
                    />
                    <Input
                      aria-label={`Port ${i + 1} host`}
                      placeholder="host"
                      inputMode="numeric"
                      value={r.host}
                      onChange={(e) => setPort(i, { host: e.target.value })}
                      className={`w-20${invalid && !isValidPort(r.host) ? " border-destructive" : ""}`}
                    />
                    <span className="w-3 text-center text-muted-foreground-2">:</span>
                    <Input
                      aria-label={`Port ${i + 1} guest`}
                      placeholder="guest"
                      inputMode="numeric"
                      value={r.guest}
                      onChange={(e) => setPort(i, { guest: e.target.value })}
                      className={`w-20${invalid && !isValidPort(r.guest) ? " border-destructive" : ""}`}
                    />
                  </>
                );
              }}
              onAdd={addPort}
              onRemove={removePort}
              addLabel="Add port"
              emptyHint="No published ports — add one to forward a port."
              rowAriaLabel={(_, i) => `Remove port ${i + 1}`}
            />
            <span className="text-xs text-muted-foreground-2">
              Bind address defaults to 127.0.0.1 when left empty.
            </span>
            {portsInvalid && (
              <span className="text-xs text-destructive">
                Each port needs a host and guest in 1–65535, and a valid IPv4 bind (or empty).
              </span>
            )}
          </div>
          <div className="grid gap-1">
            <span className="text-muted-foreground">Volumes</span>
            <EditableList
              density="card"
              items={volumeRows}
              renderRow={(row, i) => {
                const nameErr =
                  row.kind === "new_persistent" && row.name.trim() !== ""
                    ? volNameError(row.kind, row.name.trim())
                    : null;
                const pathErr =
                  row.path.trim() !== "" ? volPathError(row.path.trim()) : null;
                const sizeErr =
                  (row.kind === "ephemeral" || row.kind === "new_persistent") &&
                  row.size.trim() !== ""
                    ? volSizeError(row.kind, row.size.trim())
                    : null;
                const pickErr =
                  row.kind === "existing_persistent" && row.path.trim() !== ""
                    ? volPickError(row.kind, row.selectedVolName)
                    : null;
                return (
                  <>
                    <VolumeRowEditor
                      row={row}
                      index={i}
                      freeVolumes={freeVolumesFor(i)}
                      onChange={(r) => setVolumeRow(i, r)}
                    />
                    {nameErr && <span className="text-xs text-destructive">{nameErr}</span>}
                    {pathErr && <span className="text-xs text-destructive">{pathErr}</span>}
                    {sizeErr && <span className="text-xs text-destructive">{sizeErr}</span>}
                    {pickErr && <span className="text-xs text-destructive">{pickErr}</span>}
                  </>
                );
              }}
              onAdd={addVolume}
              onRemove={removeVolume}
              addLabel="Add volume"
              emptyHint="No volumes — add one to mount it."
              rowAriaLabel={(_, i) => `Remove volume ${i + 1}`}
            />
          </div>
        </div>

        {progress.length > 0 && (
          <div className="mt-3 max-h-24 overflow-auto rounded-lg bg-sidebar p-2 font-mono text-xs text-muted-foreground">
            {progress.map((m, i) => (
              <div key={i}>{m}</div>
            ))}
          </div>
        )}
        {error && <div className="mt-3 text-sm text-destructive">{error}</div>}

        <DialogFooter className="gap-2">
          <Button type="button" variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button
            type="button"
            disabled={!canCreate}
            aria-describedby={createBlockers.length > 0 ? "ns-create-hints" : undefined}
            onClick={() => void submit()}
          >
            {busy ? "Creating…" : "Create"}
          </Button>
        </DialogFooter>
        {createBlockers.length > 0 && (
          <div id="ns-create-hints" className="text-right text-xs text-muted-foreground-2">
            {createBlockers.map((hint) => (
              <div key={hint}>{hint}</div>
            ))}
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
