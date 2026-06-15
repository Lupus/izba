import { useEffect, useState } from "react";
import type { AllowEntry } from "../lib/types";
import { api } from "../lib/ipc";

interface Row {
  host: string;
  ports: number[];
}

/** Normalize an `AllowEntry` (string = bare host → web default ports) to a Row. */
function toRow(e: AllowEntry): Row {
  return typeof e === "string" ? { host: e, ports: [80, 443] } : { host: e.host, ports: e.ports };
}

export function PolicyEditor({ name }: { name: string }) {
  const [rows, setRows] = useState<Row[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    let alive = true;
    void (async () => {
      try {
        const p = await api.policyShow(name);
        if (alive) setRows(p.allow.map(toRow));
      } catch (e) {
        if (alive) setError(e instanceof Error ? e.message : String(e));
      }
    })();
    return () => {
      alive = false;
    };
  }, [name]);

  function setHost(i: number, host: string) {
    setRows((rs) => rs.map((r, j) => (j === i ? { ...r, host } : r)));
  }
  function setPorts(i: number, csv: string) {
    const ports = csv
      .split(",")
      .map((s) => parseInt(s.trim(), 10))
      .filter((n) => Number.isFinite(n));
    setRows((rs) => rs.map((r, j) => (j === i ? { ...r, ports } : r)));
  }
  function addRow() {
    setRows((rs) => [...rs, { host: "", ports: [443] }]);
  }
  function removeRow(i: number) {
    setRows((rs) => rs.filter((_, j) => j !== i));
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
    <div className="flex h-full flex-col gap-2">
      {error && <div className="text-sm text-warn">{error}</div>}
      {rows.map((r, i) => (
        <div key={i} className="flex items-center gap-2">
          <input
            value={r.host}
            onChange={(e) => setHost(i, e.target.value)}
            placeholder="host"
            className="rounded border border-line px-2 py-1 text-sm"
          />
          <input
            value={r.ports.join(", ")}
            onChange={(e) => setPorts(i, e.target.value)}
            placeholder="ports"
            className="w-40 rounded border border-line px-2 py-1 text-sm"
          />
          <button type="button" aria-label={`Remove ${r.host}`} onClick={() => removeRow(i)} className="text-warn">
            ✕
          </button>
        </div>
      ))}
      <div className="flex gap-2">
        <button type="button" onClick={addRow} className="rounded-lg border border-line px-3 py-1.5 hover:bg-hover">
          Add host
        </button>
        <button type="button" onClick={() => void save()} className="rounded-lg bg-accent px-3 py-1.5 font-semibold text-white">
          Save
        </button>
        {saved && <span className="self-center text-sm text-ink-2">saved · reloaded</span>}
      </div>
    </div>
  );
}
