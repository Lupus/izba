import { useMemo, useState } from "react";
import type { Access, EndpointSummary, PolicyView, SeedEntry } from "../lib/types";
import { api } from "../lib/ipc";
import { git_repo_from_row, git_op_from_path, git_access_for } from "../lib/git";
import { allowKeys } from "../lib/policy";
import { AccessPicker } from "./AccessPicker";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Switch } from "@/components/ui/switch";

interface Props {
  name: string;
  rows: EndpointSummary[];
  policy: PolicyView;
  enforcing: boolean;
  onClose: () => void;
  onApplied: () => void;
}

type CandidateKind = "git" | "http" | "raw-ip";

export interface Candidate {
  /** `kind:target` — the identity a row is deduplicated and ordered by. */
  key: string;
  kind: CandidateKind;
  label: string;
  allowCount: number;
  denyCount: number;
  defaultAccess: Access;
  /** git target string (for git rows) */
  gitTarget?: string;
  /** host (for http rows) */
  host?: string;
  port?: number;
  disabled: boolean;
}

function countLabel(c: Candidate): string {
  return c.denyCount > 0 ? `${c.allowCount}✓ ${c.denyCount}✕` : `${c.allowCount}✓`;
}

/** Total order on candidates: plain codepoint order on `key`, so the list is
 *  identical for any backend iteration order (the netlog aggregates through a
 *  HashMap, so equal-timestamp rows come back shuffled poll to poll) and for
 *  any locale. `git:` < `http:` < `raw-ip:` also puts the selectable kinds
 *  first and the disabled raw IPs last. */
function byKey(a: Candidate, b: Candidate): number {
  if (a.key < b.key) return -1;
  if (a.key > b.key) return 1;
  return 0;
}

/** The reviewable delta between what the netlog saw and what the policy already
 *  covers. Pure: same rows + policy ⇒ same list, same order. Two rows that
 *  resolve to one key (a repo seen on two ports, a clone and a push of the
 *  same repo) fold into ONE candidate — React keys must be unique, and the
 *  user is approving the target, not the row. */
export function buildCandidates(rows: EndpointSummary[], policy: PolicyView): Candidate[] {
  const allowed = allowKeys(policy.allow);
  const byKeyMap = new Map<string, Candidate>();
  const add = (c: Candidate) => {
    const prev = byKeyMap.get(c.key);
    if (!prev) {
      byKeyMap.set(c.key, c);
      return;
    }
    prev.allowCount += c.allowCount;
    prev.denyCount += c.denyCount;
    // A push widens the suggested access and names the op in the label —
    // order-independent, so the fold is deterministic.
    if (c.defaultAccess === "read-write" && prev.defaultAccess !== "read-write") {
      prev.defaultAccess = "read-write";
      prev.label = c.label;
    }
  };

  for (const row of rows) {
    const gitOp = git_op_from_path(row.last_path);
    const gitRepo = gitOp ? git_repo_from_row(row.host, row.last_path) : null;

    if (gitOp !== null && gitRepo !== null) {
      // Git row: covered if git_access_for returns non-null
      if (git_access_for(gitRepo, policy.git) !== null) continue;
      add({
        key: `git:${gitRepo}`,
        kind: "git",
        label: `git ${gitOp} → ${gitRepo}`,
        allowCount: row.allow_count,
        denyCount: row.deny_count,
        defaultAccess: gitOp === "push" ? "read-write" : "read",
        gitTarget: gitRepo,
        disabled: false,
      });
    } else if (row.host === null) {
      // Raw IP: listed but disabled
      add({
        key: `raw-ip:${row.dest_ip}:${row.port}`,
        kind: "raw-ip",
        label: `${row.dest_ip}:${row.port}`,
        allowCount: row.allow_count,
        denyCount: row.deny_count,
        defaultAccess: "read",
        disabled: true,
      });
    } else {
      // HTTP/named host row: covered if host:port is in the allow keys
      const key = `${row.host}:${row.port}`;
      if (allowed.has(key)) continue;
      const defaultAccess: Access =
        row.last_method === "GET" || row.last_method === "HEAD" || row.last_method === null
          ? "read"
          : "read-write";
      add({
        key: `http:${key}`,
        kind: "http",
        label: key,
        allowCount: row.allow_count,
        denyCount: row.deny_count,
        defaultAccess,
        host: row.host,
        port: row.port,
        disabled: false,
      });
    }
  }

  return [...byKeyMap.values()].sort(byKey);
}

export function SeedDialog({ name, rows, policy, enforcing, onClose, onApplied }: Props) {
  const candidates = useMemo(() => buildCandidates(rows, policy), [rows, policy]);

  // Selection: the set of candidate keys the user has EXPLICITLY ticked. It
  // starts EMPTY — this dialog writes straight into the sandbox's firewall
  // allow-list, so a default of "everything" would approve endpoints the user
  // never looked at. "Select all" is one deliberate click away.
  const [checked, setChecked] = useState<ReadonlySet<string>>(() => new Set());

  // access state: key → Access
  const [access, setAccess] = useState<Map<string, Access>>(() => new Map());

  const [enforceAfter, setEnforceAfter] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [applyError, setApplyError] = useState<string | null>(null);

  const toggleChecked = (key: string) => {
    setChecked((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const selectable = candidates.filter((c) => !c.disabled);
  const selectAll = () => setChecked(new Set(selectable.map((c) => c.key)));
  const deselectAll = () => setChecked(new Set());

  const setEntryAccess = (key: string, v: Access) => {
    setAccess((prev) => {
      const next = new Map(prev);
      next.set(key, v);
      return next;
    });
  };

  const selectedCandidates = selectable.filter((c) => checked.has(c.key));
  const selectedCount = selectedCandidates.length;

  async function handleAdd() {
    const entries: SeedEntry[] = selectedCandidates.map((c) => {
      const a = access.get(c.key) ?? c.defaultAccess;
      if (c.kind === "git" && c.gitTarget) {
        return { kind: "git", target: c.gitTarget, access: a };
      }
      // http
      return { kind: "http", host: c.host!, port: c.port!, access: a };
    });
    setSubmitting(true);
    setApplyError(null);
    try {
      await api.policyAddEndpoints(name, entries, enforceAfter);
      onApplied();
      onClose();
    } catch (e) {
      // Keep the dialog open and surface the error — a silently-dropped
      // firewall rule must never look like success.
      setApplyError(e instanceof Error ? e.message : String(e));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Review observed traffic</DialogTitle>
          <DialogDescription>
            Select endpoints to add to your allow-list. Already-covered entries are excluded.
          </DialogDescription>
        </DialogHeader>

        <div className="flex items-center gap-2">
          <Button variant="ghost" size="sm" onClick={selectAll} disabled={selectable.length === 0}>
            Select all
          </Button>
          <Button variant="ghost" size="sm" onClick={deselectAll} disabled={selectedCount === 0}>
            Deselect all
          </Button>
        </div>

        {candidates.length === 0 ? (
          <p className="text-sm text-muted-foreground-2">No new endpoints to add — policy already covers all observed traffic.</p>
        ) : (
          <div className="flex flex-col gap-1.5 max-h-64 overflow-y-auto">
            {candidates.map((c) => (
              <label
                key={c.key}
                className={`flex items-center gap-2 rounded-lg border border-border px-3 py-2 text-sm ${
                  c.disabled ? "opacity-50 cursor-not-allowed" : "cursor-pointer hover:bg-muted"
                }`}
              >
                <Checkbox
                  checked={!c.disabled && checked.has(c.key)}
                  disabled={c.disabled}
                  onCheckedChange={() => toggleChecked(c.key)}
                  aria-label={c.label}
                />
                <span className="flex-1 font-mono">{c.label}</span>
                <span className="text-xs text-muted-foreground-2">{countLabel(c)}</span>
                {!c.disabled && (
                  <AccessPicker
                    value={access.get(c.key) ?? c.defaultAccess}
                    onChange={(v) => setEntryAccess(c.key, v)}
                  />
                )}
                {c.disabled && (
                  <span className="text-xs text-destructive">raw IP — not selectable</span>
                )}
              </label>
            ))}
          </div>
        )}

        {/* Enforce-after switch — prominent when firewall is off */}
        {!enforcing ? (
          <div className="rounded-lg border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">
            <p className="mb-1 font-semibold">⚠ firewall is currently OFF</p>
            <label className="flex items-center gap-2 cursor-pointer">
              <Switch
                checked={enforceAfter}
                onCheckedChange={setEnforceAfter}
                aria-label="Enforce firewall after adding"
              />
              Enforce firewall after adding
            </label>
          </div>
        ) : (
          <div>
            <label className="flex items-center gap-2 text-sm text-muted-foreground cursor-not-allowed">
              <Switch
                checked={enforceAfter}
                disabled
                onCheckedChange={setEnforceAfter}
                aria-label="Enforce firewall after adding"
              />
              Enforce firewall after adding
            </label>
          </div>
        )}

        {applyError && (
          <div role="alert" className="text-sm text-destructive">
            Failed to apply: {applyError}
          </div>
        )}

        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant="default"
            disabled={submitting || selectedCount === 0}
            onClick={() => void handleAdd()}
          >
            {`Add ${selectedCount} selected to allow-list`}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
