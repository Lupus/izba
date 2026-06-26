import { useEffect, useRef, useState } from "react";
import { X } from "lucide-react";
import type { Access, AllowEntry, GitRule } from "../lib/types";
import { api } from "../lib/ipc";
import { WEB_DEFAULT_PORTS } from "../lib/ports";
import { AccessPicker } from "./AccessPicker";
import { Section } from "./Section";
import { EnforceToggle } from "./EnforceToggle";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { EditableList } from "@/components/ui/editable-list";

interface Row {
  host: string;
  ports: number[];
  access: Access;
}

interface GitRow {
  /** The raw glob string ("host/owner/repo" or "host") */
  target: string;
  access: Access;
}

/** Extract the glob string from a GitRule. */
function gitRuleTarget(rule: GitRule): string {
  return "repo" in rule ? rule.repo : rule.host;
}

function toGitRow(rule: GitRule): GitRow {
  return { target: gitRuleTarget(rule), access: rule.access ?? "read" };
}

/** Normalize an `AllowEntry` (string = bare host → web default ports) to a Row. */
function toRow(e: AllowEntry): Row {
  return typeof e === "string"
    ? { host: e, ports: [...WEB_DEFAULT_PORTS], access: "read-write" }
    : { host: e.host, ports: e.ports ?? [...WEB_DEFAULT_PORTS], access: e.access ?? "read-write" };
}

/** Convert a target string and access into a GitRule. */
function toGitRule(target: string, access: Access): GitRule {
  return target.includes("/") ? { repo: target, access } : { host: target, access };
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
          <Badge key={p} variant="secondary" className="gap-1">
            {p}
            {/* Intentional in-chip remove button — distinct from row-level RemoveRowButton idiom */}
            <Button
              type="button"
              variant="ghost"
              size="icon"
              aria-label={`Remove port ${p}`}
              onClick={() => onRemove(p)}
              className="h-3.5 w-3.5 p-0 text-muted-foreground-2 hover:text-destructive"
            >
              <X className="h-3 w-3" />
            </Button>
          </Badge>
        ))}
        <Input
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
          className="w-20 py-1 text-xs"
        />
        <Button
          type="button"
          variant="secondary"
          size="sm"
          onClick={commit}
        >
          Add
        </Button>
      </div>
      {err && <span className="text-xs text-destructive">{err}</span>}
    </div>
  );
}

interface LoadedSnapshot {
  hosts: Row[];
  git: GitRow[];
}

export function PolicyEditor({ name }: { name: string }) {
  const [hosts, setHosts] = useState<Row[]>([]);
  const [gitRows, setGitRows] = useState<GitRow[]>([]);
  const [enforcing, setEnforcing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const loadedRef = useRef<LoadedSnapshot>({ hosts: [], git: [] });

  // Derive dirty: current state differs from the last-saved/loaded snapshot.
  const dirty =
    JSON.stringify({ hosts, git: gitRows }) !==
    JSON.stringify({ hosts: loadedRef.current.hosts, git: loadedRef.current.git });

  useEffect(() => {
    let alive = true;
    void (async () => {
      try {
        const p = await api.policyShow(name);
        if (alive) {
          const loadedHosts = p.allow.map(toRow);
          const loadedGit = p.git.map(toGitRow);
          setHosts(loadedHosts);
          setEnforcing(p.enforcing);
          setGitRows(loadedGit);
          loadedRef.current = { hosts: loadedHosts, git: loadedGit };
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

  // Host row helpers
  function editHosts(f: (rs: Row[]) => Row[]) {
    setHosts(f);
    setSaved(false);
  }
  function setHost(i: number, host: string) {
    editHosts((rs) => rs.map((r, j) => (j === i ? { ...r, host } : r)));
  }
  function addPort(i: number, port: number) {
    editHosts((rs) =>
      rs.map((r, j) =>
        j === i && !r.ports.includes(port)
          ? { ...r, ports: [...r.ports, port].sort((a, b) => a - b) }
          : r,
      ),
    );
  }
  function removePort(i: number, port: number) {
    editHosts((rs) => rs.map((r, j) => (j === i ? { ...r, ports: r.ports.filter((p) => p !== port) } : r)));
  }
  function addRow() {
    editHosts((rs) => [...rs, { host: "", ports: [443], access: "read-write" }]);
  }
  function removeRow(i: number) {
    editHosts((rs) => rs.filter((_, j) => j !== i));
  }
  function setHostAccess(i: number, access: Access) {
    editHosts((rs) => rs.map((r, j) => (j === i ? { ...r, access } : r)));
  }

  // Git row helpers
  function editGit(f: (rs: GitRow[]) => GitRow[]) {
    setGitRows(f);
    setSaved(false);
  }
  function addGitRow() {
    editGit((rs) => [...rs, { target: "", access: "read" }]);
  }
  function removeGitRow(i: number) {
    editGit((rs) => rs.filter((_, j) => j !== i));
  }
  function setGitTarget(i: number, target: string) {
    editGit((rs) => rs.map((r, j) => (j === i ? { ...r, target } : r)));
  }
  function setGitAccess(i: number, access: Access) {
    editGit((rs) => rs.map((r, j) => (j === i ? { ...r, access } : r)));
  }

  async function save() {
    setError(null);
    setSaved(false);
    try {
      const allow: AllowEntry[] = hosts
        .filter((r) => r.host.trim() !== "")
        .map((r) => ({ host: r.host.trim(), ports: r.ports, access: r.access }));
      const git: GitRule[] = gitRows
        .filter((r) => r.target.trim() !== "")
        .map((r) => toGitRule(r.target.trim(), r.access));
      await api.policySetFull(name, allow, git);
      // Refresh the loaded snapshot and mark saved.
      loadedRef.current = { hosts, git: gitRows };
      setSaved(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <div className="flex h-full flex-col">
      {/* Enforce toggle — always visible above the scroll area */}
      <div className="flex shrink-0 items-center gap-3 pb-3">
        <EnforceToggle enforcing={enforcing} onToggle={() => void toggleEnforce()} />
      </div>
      {error && <div className="shrink-0 pb-3 text-sm text-destructive">{error}</div>}

      {/* Scrollable sections area — flexes to fill available height */}
      <div className="min-h-0 flex-1 overflow-y-auto">
        <div className="flex flex-col gap-3 pb-3">
          <Section title="Hosts">
            <p className="mb-2 text-sm text-muted-foreground">
              Hosts this sandbox may reach. Add a port to a host, or remove one with its ✕.
            </p>
            <EditableList
              density="card"
              items={hosts}
              renderRow={(r, i) => (
                <>
                  <div className="flex w-full items-center gap-2">
                    <label className="w-12 shrink-0 text-xs font-semibold text-muted-foreground">Host</label>
                    <Input
                      value={r.host}
                      onChange={(e) => setHost(i, e.target.value)}
                      placeholder="api.example.com"
                      className="flex-1 font-mono text-sm"
                    />
                  </div>
                  <div className="flex w-full items-center gap-2">
                    <label className="w-12 shrink-0 text-xs font-semibold text-muted-foreground">Ports</label>
                    <PortEditor
                      ports={r.ports}
                      onAdd={(p) => addPort(i, p)}
                      onRemove={(p) => removePort(i, p)}
                    />
                  </div>
                  <div className="flex w-full items-center gap-2">
                    <label className="w-12 shrink-0 text-xs font-semibold text-muted-foreground">Access</label>
                    <AccessPicker
                      value={r.access}
                      onChange={(v) => setHostAccess(i, v)}
                    />
                  </div>
                </>
              )}
              onAdd={addRow}
              onRemove={(i) => removeRow(i)}
              addLabel="Add host"
              emptyHint="No allowed hosts — add one to permit egress."
              rowAriaLabel={(_,i) => `Remove host ${i + 1}`}
            />
          </Section>

          <Section title="Git repos">
            <p className="mb-2 text-sm text-muted-foreground">
              Git repositories this sandbox may clone or push to. Specify as{" "}
              <span className="font-mono">host/owner/repo</span> or <span className="font-mono">host</span>.
            </p>
            <EditableList
              density="card"
              items={gitRows}
              renderRow={(gr, i) => (
                <div className="flex w-full items-center gap-2">
                  <Input
                    value={gr.target}
                    onChange={(e) => setGitTarget(i, e.target.value)}
                    placeholder="github.com/owner/repo"
                    className="flex-1 font-mono text-sm"
                  />
                  <AccessPicker
                    value={gr.access}
                    onChange={(v) => setGitAccess(i, v)}
                  />
                </div>
              )}
              onAdd={addGitRow}
              onRemove={(i) => removeGitRow(i)}
              addLabel="Add repo"
              emptyHint="No git rules — add one to allow a repo."
              rowAriaLabel={(_,i) => `Remove repo ${i + 1}`}
            />
          </Section>
        </div>
      </div>

      {/* Save footer — always visible, never scrolls away */}
      <div className="flex shrink-0 items-center gap-2 border-t border-border pt-3">
        <Button
          type="button"
          onClick={() => void save()}
        >
          Save
        </Button>
        {dirty && <span className="self-center text-sm text-muted-foreground">● unsaved changes</span>}
        {saved && !dirty && <span className="self-center text-sm text-muted-foreground">saved · reloaded</span>}
      </div>
    </div>
  );
}
