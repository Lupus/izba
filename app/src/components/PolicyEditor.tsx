import { useEffect, useState } from "react";
import type { AllowEntry } from "../lib/types";
import { api } from "../lib/ipc";
import { WEB_DEFAULT_PORTS } from "../lib/ports";

interface Row {
  host: string;
  ports: number[];
}

/** Normalize an `AllowEntry` (string = bare host → web default ports) to a Row. */
function toRow(e: AllowEntry): Row {
  return typeof e === "string"
    ? { host: e, ports: [...WEB_DEFAULT_PORTS] }
    : { host: e.host, ports: e.ports };
}

/** Per-host ports shown as removable chips plus a numeric "add port" field. */
function PortEditor({
  ports,
  onAdd,
  onRemove,
}: {
  ports: number[];
  onAdd: (port: number) => void;
  onRemove: (port: number) => void;
}) {
  const [draft, setDraft] = useState("");
  const [err, setErr] = useState<string | null>(null);
  function commit() {
    const t = draft.trim();
    if (!t) return; // empty field is a no-op, not an error (e.g. a stray Add click)
    if (!/^\d+$/.test(t)) {
      setErr("Enter a port between 1 and 65535.");
      return; // keep the draft so the user can fix it
    }
    const p = parseInt(t, 10);
    if (p < 1 || p > 65535) {
      setErr("Enter a port between 1 and 65535.");
      return;
    }
    if (ports.includes(p)) {
      setErr(`Port ${p} is already added.`);
      return;
    }
    onAdd(p);
    setDraft("");
    setErr(null);
  }
  return (
    <div className="flex flex-1 flex-col gap-1">
      <div className="flex flex-wrap items-center gap-1">
        {ports.map((p) => (
          <span
            key={p}
            className="inline-flex items-center gap-1 rounded bg-hover px-2 py-0.5 text-xs font-mono"
          >
            {p}
            <button
              type="button"
              aria-label={`Remove port ${p}`}
              onClick={() => onRemove(p)}
              className="text-ink-3 hover:text-warn"
            >
              ✕
            </button>
          </span>
        ))}
        <input
          value={draft}
          onChange={(e) => {
            setDraft(e.target.value);
            if (err) setErr(null);
          }}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              commit();
            }
          }}
          placeholder="add port"
          aria-label="add port"
          inputMode="numeric"
          className="w-20 rounded border border-line px-2 py-1 text-xs"
        />
        <button
          type="button"
          onClick={commit}
          className="rounded border border-line px-2 py-1 text-xs text-ink-2 hover:bg-hover"
        >
          Add
        </button>
      </div>
      {err && <span className="text-xs text-warn">{err}</span>}
    </div>
  );
}

export function PolicyEditor({ name }: { name: string }) {
  const [rows, setRows] = useState<Row[]>([]);
  const [enforcing, setEnforcing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    let alive = true;
    void (async () => {
      try {
        const p = await api.policyShow(name);
        if (alive) {
          setRows(p.allow.map(toRow));
          setEnforcing(p.enforcing);
        }
      } catch (e) {
        if (alive) setError(e instanceof Error ? e.message : String(e));
      }
    })();
    return () => {
      alive = false;
    };
  }, [name]);

  async function toggleEnforce() {
    const next = !enforcing;
    setEnforcing(next);
    try {
      await api.policySetEnforce(name, next);
    } catch (e) {
      // revert on error
      setEnforcing(!next);
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  // Any edit invalidates the "saved" confirmation so it doesn't linger.
  function edit(f: (rs: Row[]) => Row[]) {
    setRows(f);
    setSaved(false);
  }
  function setHost(i: number, host: string) {
    edit((rs) => rs.map((r, j) => (j === i ? { ...r, host } : r)));
  }
  function addPort(i: number, port: number) {
    edit((rs) =>
      rs.map((r, j) =>
        j === i && !r.ports.includes(port)
          ? { ...r, ports: [...r.ports, port].sort((a, b) => a - b) }
          : r,
      ),
    );
  }
  function removePort(i: number, port: number) {
    edit((rs) => rs.map((r, j) => (j === i ? { ...r, ports: r.ports.filter((p) => p !== port) } : r)));
  }
  function addRow() {
    edit((rs) => [...rs, { host: "", ports: [443] }]);
  }
  function removeRow(i: number) {
    edit((rs) => rs.filter((_, j) => j !== i));
  }

  async function save() {
    setError(null);
    setSaved(false);
    try {
      const allow: AllowEntry[] = rows
        .filter((r) => r.host.trim() !== "")
        .map((r) => ({ host: r.host.trim(), ports: r.ports }));
      await api.policySet(name, allow);
      setSaved(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <div className="flex h-full flex-col gap-3">
      <div className="flex items-center gap-3">
        <label className="flex cursor-pointer items-center gap-2 text-sm font-semibold">
          <input
            type="checkbox"
            role="checkbox"
            aria-label="Enforce firewall"
            checked={enforcing}
            onChange={() => void toggleEnforce()}
            className="h-4 w-4 rounded border-line"
          />
          Enforce firewall
        </label>
      </div>
      <p className="text-sm text-ink-2">
        Hosts this sandbox may reach. Add a port to a host, or remove one with its ✕.
      </p>
      {error && <div className="text-sm text-warn">{error}</div>}
      <fieldset disabled={!enforcing} className="contents">
        <div className="flex flex-col gap-2">
          {rows.map((r, i) => (
            <div key={i} className="flex flex-col gap-2 rounded-lg border border-line p-3">
              <div className="flex items-center gap-2">
                <label className="w-12 shrink-0 text-xs font-semibold text-ink-2">Host</label>
                <input
                  value={r.host}
                  onChange={(e) => setHost(i, e.target.value)}
                  placeholder="api.example.com"
                  className="flex-1 rounded border border-line px-2 py-1 text-sm font-mono"
                />
                <button
                  type="button"
                  aria-label={`Remove host ${r.host}`}
                  onClick={() => removeRow(i)}
                  className="rounded border border-warn/40 px-2 py-1 text-xs text-warn hover:bg-warn/5"
                >
                  Remove
                </button>
              </div>
              <div className="flex items-center gap-2">
                <label className="w-12 shrink-0 text-xs font-semibold text-ink-2">Ports</label>
                <PortEditor
                  ports={r.ports}
                  onAdd={(p) => addPort(i, p)}
                  onRemove={(p) => removePort(i, p)}
                />
              </div>
            </div>
          ))}
          {rows.length === 0 && (
            <div className="text-sm text-ink-3">No hosts allowed yet — add one below.</div>
          )}
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={addRow}
            className="rounded-lg border border-line px-3 py-1.5 hover:bg-hover"
          >
            Add host
          </button>
          <button
            type="button"
            onClick={() => void save()}
            className="rounded-lg bg-accent px-3 py-1.5 font-semibold text-white"
          >
            Save
          </button>
          {saved && <span className="self-center text-sm text-ink-2">saved · reloaded</span>}
        </div>
      </fieldset>
    </div>
  );
}
