import { useEffect, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { api, onCreateProgress } from "../lib/ipc";
import type { CreateOpts, VolumeInfo } from "../lib/types";
import { isValidPort, isValidBind } from "../lib/portvalidate";
import {
  type VolumeRow,
  defaultVolumeRow,
  buildVolSpec,
  isBlankVolRow,
  isValidVolRow,
  volNameError,
  volPathError,
  volSizeError,
  volPickError,
} from "../lib/volumevalidate";
import { VolumeRowEditor } from "./VolumeRowEditor";

interface Props {
  onClose: () => void;
  onCreated: (name: string) => void;
}

interface PortRow {
  bind: string;
  host: string;
  guest: string;
}

export function NewSandbox({ onClose, onCreated }: Props) {
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

  // Escape key and backdrop close
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [onClose]);

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

  // Free volumes for each row: exclude referenced + names used in other rows as existing_persistent.
  function freeVolumesFor(rowIdx: number): VolumeInfo[] {
    const usedNames = new Set(
      volumeRows
        .filter((r, i) => i !== rowIdx && r.kind === "existing_persistent")
        .map((r) => r.selectedVolName)
        .filter(Boolean),
    );
    return allVolumes.filter((v) => v.referenced_by.length === 0 && !usedNames.has(v.name));
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
  // "+ Add port" click can't block submit). Any row they started filling must
  // carry numeric host AND guest ports in 1–65535, plus a valid IPv4 bind (or
  // empty → the daemon defaults it to 127.0.0.1). The bind contract mirrors
  // izba_core::portfwd::parse_rule, which parses bind as an Ipv4Addr.
  const isBlankRow = (r: PortRow) => !r.bind.trim() && !r.host.trim() && !r.guest.trim();
  const isValidRow = (r: PortRow) =>
    isValidPort(r.host) && isValidPort(r.guest) && isValidBind(r.bind);
  const portsInvalid = ports.some((r) => !isBlankRow(r) && !isValidRow(r));

  const volumesInvalid = volumeRows.some((r) => !isBlankVolRow(r) && !isValidVolRow(r));

  const canCreate =
    name.trim().length > 0 &&
    workspace.trim().length > 0 &&
    !busy &&
    !portsInvalid &&
    !volumesInvalid;

  // Shared column template so the Bind/Host/Guest headers line up with the
  // inputs below: [bind grows] [host 5rem] [colon] [guest 5rem] [remove 2rem].
  const portGrid = "grid grid-cols-[minmax(0,1fr)_5rem_0.75rem_5rem_2rem] items-center gap-1.5";

  return (
    <div
      className="fixed inset-0 z-50 grid place-items-center bg-black/30"
      role="dialog"
      aria-modal="true"
      aria-label="New sandbox"
    >
      {/* Full-screen backdrop button: click outside the panel closes. Native button = keyboard+screenreader accessible. */}
      <button
        type="button"
        aria-label="Close dialog"
        onClick={onClose}
        className="absolute inset-0 cursor-default"
        tabIndex={-1}
      />
      <div
        className="relative w-[32rem] max-w-[92vw] rounded-xl bg-surface p-5 shadow-xl max-h-[90vh] overflow-y-auto"
      >
        <h2 className="text-lg font-semibold">New sandbox</h2>
        <div className="mt-4 grid gap-3 text-sm">
          <label className="grid gap-1">
            <span className="text-ink-2">Name</span>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full min-w-0 rounded-lg border border-line px-2 py-1.5"
            />
          </label>
          <div className="grid gap-1">
            <span className="text-ink-2">Workspace</span>
            <div className="flex gap-2">
              <input
                aria-label="Workspace"
                value={workspace}
                onChange={(e) => setWorkspace(e.target.value)}
                className="flex-1 rounded-lg border border-line px-2 py-1.5"
              />
              <button
                type="button"
                onClick={() => void pickDir()}
                className="rounded-lg border border-line px-3 hover:bg-hover"
              >
                Browse…
              </button>
            </div>
          </div>
          <label className="grid gap-1">
            <span className="text-ink-2">Image</span>
            <input
              value={image}
              onChange={(e) => setImage(e.target.value)}
              className="w-full min-w-0 rounded-lg border border-line px-2 py-1.5"
            />
          </label>
          <div className="grid grid-cols-3 gap-3">
            <label className="grid gap-1">
              <span className="text-ink-2">vCPUs</span>
              <input
                type="number"
                min={1}
                value={cpus}
                onChange={(e) => setCpus(+e.target.value)}
                className="w-full min-w-0 rounded-lg border border-line px-2 py-1.5"
              />
            </label>
            <label className="grid gap-1">
              <span className="text-ink-2">Memory (MiB)</span>
              <input
                type="number"
                min={256}
                value={memMb}
                onChange={(e) => setMemMb(+e.target.value)}
                className="w-full min-w-0 rounded-lg border border-line px-2 py-1.5"
              />
            </label>
            <label className="grid gap-1">
              <span className="text-ink-2">Disk (GiB)</span>
              <input
                type="number"
                min={1}
                value={rwSizeGb}
                onChange={(e) => setRwSizeGb(+e.target.value)}
                className="w-full min-w-0 rounded-lg border border-line px-2 py-1.5"
              />
            </label>
          </div>
          <div className="grid gap-1">
            <span className="text-ink-2">Ports</span>
            <div className="grid gap-1.5">
              {ports.length > 0 && (
                <div className={portGrid + " text-xs text-ink-3"}>
                  <span>Bind address</span>
                  <span>Host port</span>
                  <span />
                  <span>Guest port</span>
                  <span />
                </div>
              )}
              {ports.map((r, i) => {
                const invalid = !isBlankRow(r) && !isValidRow(r);
                // Shared cell style; flag the specific field that is wrong.
                const cell = (bad: boolean) =>
                  "w-full min-w-0 rounded-lg border px-2 py-1.5 text-xs " +
                  (bad ? "border-warn" : "border-line");
                return (
                  <div key={i} className={portGrid}>
                    <input
                      aria-label={`Port ${i + 1} bind`}
                      placeholder="127.0.0.1"
                      value={r.bind}
                      onChange={(e) => setPort(i, { bind: e.target.value })}
                      className={cell(invalid && !isValidBind(r.bind))}
                    />
                    <input
                      aria-label={`Port ${i + 1} host`}
                      placeholder="host"
                      inputMode="numeric"
                      value={r.host}
                      onChange={(e) => setPort(i, { host: e.target.value })}
                      className={cell(invalid && !isValidPort(r.host))}
                    />
                    <span className="text-center text-ink-3">:</span>
                    <input
                      aria-label={`Port ${i + 1} guest`}
                      placeholder="guest"
                      inputMode="numeric"
                      value={r.guest}
                      onChange={(e) => setPort(i, { guest: e.target.value })}
                      className={cell(invalid && !isValidPort(r.guest))}
                    />
                    <button
                      type="button"
                      aria-label={`Remove port ${i + 1}`}
                      onClick={() => removePort(i)}
                      className="w-full rounded-lg border border-line py-1.5 text-ink-2 hover:bg-hover"
                    >
                      ×
                    </button>
                  </div>
                );
              })}
              <button
                type="button"
                onClick={addPort}
                className="justify-self-start rounded-lg border border-line px-2 py-1 text-xs text-ink-2 hover:bg-hover"
              >
                + Add port
              </button>
              <span className="text-xs text-ink-3">
                Bind address defaults to 127.0.0.1 when left empty.
              </span>
              {portsInvalid && (
                <span className="text-xs text-warn">
                  Each port needs a host and guest in 1–65535, and a valid IPv4 bind (or empty).
                </span>
              )}
            </div>
          </div>
          <div className="grid gap-1">
            <span className="text-ink-2">Volumes</span>
            <div className="grid gap-1.5">
              {volumeRows.map((row, i) => {
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
                  <div key={i} className="grid gap-1">
                    <VolumeRowEditor
                      row={row}
                      index={i}
                      freeVolumes={freeVolumesFor(i)}
                      onChange={(r) => setVolumeRow(i, r)}
                      onRemove={() => removeVolume(i)}
                    />
                    {nameErr && <span className="text-xs text-warn">{nameErr}</span>}
                    {pathErr && <span className="text-xs text-warn">{pathErr}</span>}
                    {sizeErr && <span className="text-xs text-warn">{sizeErr}</span>}
                    {pickErr && <span className="text-xs text-warn">{pickErr}</span>}
                  </div>
                );
              })}
              <button
                type="button"
                onClick={addVolume}
                className="justify-self-start rounded-lg border border-line px-2 py-1 text-xs text-ink-2 hover:bg-hover"
              >
                + Add volume
              </button>
            </div>
          </div>
        </div>

        {progress.length > 0 && (
          <div className="mt-3 max-h-24 overflow-auto rounded-lg bg-rail p-2 font-mono text-xs text-ink-2">
            {progress.map((m, i) => (
              <div key={i}>{m}</div>
            ))}
          </div>
        )}
        {error && <div className="mt-3 text-warn text-sm">{error}</div>}

        <div className="mt-5 flex justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg px-3 py-1.5 text-ink-2 hover:bg-hover"
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={!canCreate}
            onClick={() => void submit()}
            className="rounded-lg bg-accent px-3 py-1.5 font-semibold text-white shadow-sm disabled:opacity-50"
          >
            {busy ? "Creating…" : "Create"}
          </button>
        </div>
      </div>
    </div>
  );
}
