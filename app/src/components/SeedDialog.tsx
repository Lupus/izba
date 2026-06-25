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

interface Candidate {
  key: string;
  kind: CandidateKind;
  label: string;
  countLabel: string;
  defaultAccess: Access;
  /** git target string (for git rows) */
  gitTarget?: string;
  /** host (for http rows) */
  host?: string;
  port?: number;
  disabled: boolean;
}

function buildCandidates(rows: EndpointSummary[], policy: PolicyView): Candidate[] {
  const allowed = allowKeys(policy.allow);
  const candidates: Candidate[] = [];

  for (const row of rows) {
    const gitOp = git_op_from_path(row.last_path);
    const gitRepo = gitOp ? git_repo_from_row(row.host, row.last_path) : null;
    const isGit = gitOp !== null && gitRepo !== null;

    if (isGit && gitRepo) {
      // Git row: covered if git_access_for returns non-null
      if (git_access_for(gitRepo, policy.git) !== null) continue;
      const defaultAccess: Access = gitOp === "push" ? "read-write" : "read";
      const countLabel =
        row.deny_count > 0 ? `${row.allow_count}✓ ${row.deny_count}✕` : `${row.allow_count}✓`;
      candidates.push({
        key: `git:${gitRepo}`,
        kind: "git",
        label: `git ${gitOp} → ${gitRepo}`,
        countLabel,
        defaultAccess,
        gitTarget: gitRepo,
        disabled: false,
      });
    } else if (row.host === null) {
      // Raw IP: listed but disabled
      const countLabel =
        row.deny_count > 0 ? `${row.allow_count}✓ ${row.deny_count}✕` : `${row.allow_count}✓`;
      candidates.push({
        key: `raw-ip:${row.dest_ip}:${row.port}`,
        kind: "raw-ip",
        label: `${row.dest_ip}:${row.port}`,
        countLabel,
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
      const countLabel =
        row.deny_count > 0 ? `${row.allow_count}✓ ${row.deny_count}✕` : `${row.allow_count}✓`;
      candidates.push({
        key: `http:${key}`,
        kind: "http",
        label: `${row.host}:${row.port}`,
        countLabel,
        defaultAccess,
        host: row.host,
        port: row.port,
        disabled: false,
      });
    }
  }

  return candidates;
}

export function SeedDialog({ name, rows, policy, enforcing, onClose, onApplied }: Props) {
  const candidates = useMemo(() => buildCandidates(rows, policy), [rows, policy]);

  // checked state: key → bool (default true for non-disabled)
  const [checked, setChecked] = useState<Map<string, boolean>>(() => {
    const m = new Map<string, boolean>();
    for (const c of candidates) {
      m.set(c.key, !c.disabled);
    }
    return m;
  });

  // access state: key → Access
  const [access, setAccess] = useState<Map<string, Access>>(() => {
    const m = new Map<string, Access>();
    for (const c of candidates) {
      m.set(c.key, c.defaultAccess);
    }
    return m;
  });

  const [enforceAfter, setEnforceAfter] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [applyError, setApplyError] = useState<string | null>(null);

  const toggleChecked = (key: string) => {
    setChecked((prev) => {
      const next = new Map(prev);
      next.set(key, !next.get(key));
      return next;
    });
  };

  const setEntryAccess = (key: string, v: Access) => {
    setAccess((prev) => {
      const next = new Map(prev);
      next.set(key, v);
      return next;
    });
  };

  const selectedCandidates = candidates.filter((c) => !c.disabled && checked.get(c.key));
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
                {/* eslint-disable-next-line izba/no-raw-control -- no Checkbox primitive available */}
                <input
                  type="checkbox"
                  checked={!c.disabled && (checked.get(c.key) ?? false)}
                  disabled={c.disabled}
                  onChange={() => toggleChecked(c.key)}
                  className="shrink-0"
                />
                <span className="flex-1 font-mono">{c.label}</span>
                <span className="text-xs text-muted-foreground-2">{c.countLabel}</span>
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
          <div className="rounded-lg border border-amber-400 bg-amber-50 px-3 py-2 text-sm text-amber-900">
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
            {selectedCount > 0 ? `Add ${selectedCount} selected to allow-list` : "Add selected to allow-list"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
