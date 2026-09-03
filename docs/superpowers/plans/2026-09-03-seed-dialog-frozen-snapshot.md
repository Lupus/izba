# SeedDialog Frozen Snapshot Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the desktop app's "Review observed traffic" dialog a frozen, deterministically ordered snapshot with nothing selected by default, an explicit refresh, and a non-blocking "new traffic observed" notice (issue #286).

**Architecture:** All behaviour lands inside `app/src/components/SeedDialog.tsx`. `NetlogView` keeps polling and keeps passing live `rows`/`policy` props; the dialog captures its candidate list ONCE into React state at mount (`useState` initializer), renders only that snapshot, and uses the live props solely to count endpoints the snapshot has not seen. A pure, exported `buildCandidates` produces a deduplicated, key-sorted list so order is a total order independent of backend iteration. Selection is a `Set<string>` that starts empty.

**Tech Stack:** React 18 + TypeScript, shadcn/Radix `Dialog`/`Checkbox`/`Button`, Vitest + Testing Library (jsdom unit project), Playwright e2e against the scripted Tauri IPC mock (`app/e2e/mock/tauri-mock.js`, `mock.setScenario`).

**Spec:** GitHub issue #286 (https://github.com/Lupus/izba/issues/286) — its `### In Scope` / `### Acceptance Criteria` are the requirements; `docs/superpowers/plans/2026-06-18-policy-netlog-ux-redesign.md` is the original SeedDialog design (Task 7 there), which this plan amends.

## Global Constraints

- Out of scope (issue): the per-row Allow/Block actions in the netlog table stay immediate; the CLI `policy seed` flow is untouched; which endpoints qualify as candidates is unchanged (only dedupe + order + when the list is observed).
- No hover/pointer dependence: every control must be a real `button` / `checkbox` reachable by Tab and activated by Space/Enter. Nothing may live only in `onMouseEnter`/`title`.
- No new Tauri command, no wire change: `api.policyAddEndpoints(name, entries, enforce)` stays the only write. `app/src/test/tauriMockParity.test.ts` must stay green untouched.
- App gate (must be green before every commit, run from `app/`): `npm run lint && npm run build && npm run test` (lint is `eslint . --max-warnings 0`). Playwright: `npx playwright test e2e/netlog.spec.ts --project=chromium` (also `--project=webkit` when installed; CI Linux runs both).
- Conventional commits; every commit body carries `Refs #286`.
- Existing behaviour that MUST survive: covered hosts/repos excluded; raw-IP rows listed but disabled and never submitted; "Enforce firewall after adding" switch semantics; apply error keeps the dialog open with `role="alert"`.
- Copy: the user-facing strings are exactly `Select all`, `Deselect all`, `Refresh`, `Add N selected to allow-list` (N may be 0), and `N new endpoint(s) observed since this review — refresh to include them.`

---

### Task 1: Deterministic candidates, empty default selection, Select all / Deselect all

**Files:**
- Modify: `app/src/components/SeedDialog.tsx` (whole `buildCandidates` + state block + footer)
- Test: `app/src/test/seedDialog.test.tsx`

**Interfaces:**
- Consumes: `EndpointSummary`, `PolicyView`, `Access`, `SeedEntry` from `app/src/lib/types.ts`; `allowKeys` from `app/src/lib/policy.ts`; `git_repo_from_row`, `git_op_from_path`, `git_access_for` from `app/src/lib/git.ts`.
- Produces: `export interface Candidate { key: string; kind: "git" | "http" | "raw-ip"; label: string; allowCount: number; denyCount: number; defaultAccess: Access; gitTarget?: string; host?: string; port?: number; disabled: boolean }` and `export function buildCandidates(rows: EndpointSummary[], policy: PolicyView): Candidate[]` (deduplicated by `key`, sorted by `key` codepoint order). Task 2 relies on both names.

- [ ] **Step 1: Write the failing tests**

Replace the top of `app/src/test/seedDialog.test.tsx` imports so `buildCandidates` and `within` are available, and adjust the existing five tests so they select explicitly (nothing is pre-selected any more), then append the new suites. Full file after the change:

```tsx
import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach } from "vitest";
import type { Mock } from "vitest";
import { SeedDialog, buildCandidates } from "../components/SeedDialog";
import { api } from "../lib/ipc";
import type { EndpointSummary } from "../lib/types";

vi.mock("../lib/ipc", () => ({
  api: {
    policyAddEndpoints: vi.fn(),
  },
}));

/** Minimal EndpointSummary factory — only supply what differs per test. */
function sum(overrides: Partial<EndpointSummary>): EndpointSummary {
  return {
    host: "example.com",
    dest_ip: "1.2.3.4",
    port: 443,
    tier: "l7",
    verdict: "allow",
    allow_count: 1,
    deny_count: 0,
    first_seen_ms: 1,
    last_seen_ms: 9,
    last_method: "GET",
    last_path: "/",
    ...overrides,
  };
}

const bare = { enforcing: false, allow: [], git: [] };

/** The dialog's candidate rows, top to bottom, as their accessible names. */
function listedLabels(): string[] {
  return screen
    .getAllByRole("checkbox")
    .map((cb) => cb.getAttribute("aria-label") ?? "");
}

function addButton(): HTMLElement {
  return screen.getByRole("button", { name: /^Add \d+ selected to allow-list$/ });
}

beforeEach(() => {
  vi.clearAllMocks();
  (api.policyAddEndpoints as Mock).mockResolvedValue(undefined);
});

describe("SeedDialog", () => {
  it("lists only the delta and adds selected via policyAddEndpoints", async () => {
    const add = api.policyAddEndpoints as Mock;
    const rows = [
      sum({ host: "pypi.org", port: 443, last_method: "GET", last_path: "/simple/" }),
      sum({ host: "api.x.com", port: 443, last_method: "POST", last_path: "/v1" }), // already in policy
    ];
    render(<SeedDialog name="web" rows={rows} enforcing={false}
      policy={{ enforcing:false, allow:[{host:"api.x.com",ports:[443]}], git:[] }}
      onClose={()=>{}} onApplied={()=>{}} />);
    expect(screen.queryByText(/api\.x\.com/)).toBeNull();          // covered → excluded
    expect(screen.getByText(/pypi\.org/)).toBeInTheDocument();      // delta
    fireEvent.click(screen.getByRole("checkbox", { name: "pypi.org:443" }));
    fireEvent.click(addButton());
    await waitFor(() => expect(add).toHaveBeenCalledWith("web",
      [{ kind: "http", host: "pypi.org", port: 443, access: "read" }], false));
  });

  it("enforce-after checkbox is prominent when firewall is off and passes enforce=true when checked", async () => {
    const add = api.policyAddEndpoints as Mock;
    render(<SeedDialog name="web" rows={[sum({host:"pypi.org",port:443,last_method:"GET",last_path:"/"})]}
      enforcing={false} policy={bare} onClose={()=>{}} onApplied={()=>{}} />);
    expect(screen.getByText(/firewall is currently OFF/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("switch", { name: /Enforce firewall after adding/i }));
    fireEvent.click(screen.getByRole("button", { name: "Select all" }));
    fireEvent.click(addButton());
    await waitFor(() => expect(add).toHaveBeenCalledWith("web", expect.anything(), true));
  });

  it("git delta exclusion: covered repo excluded, uncovered repo listed", async () => {
    const add = api.policyAddEndpoints as Mock;
    const rows = [
      // Covered by policy.git — should be excluded from candidates
      sum({ host: "github.com", last_method: "POST", last_path: "/o/a/git-upload-pack" }),
      // Not covered by policy.git — should appear in candidates
      sum({ host: "github.com", last_method: "POST", last_path: "/o/b/git-upload-pack" }),
    ];
    render(
      <SeedDialog name="web" rows={rows} enforcing={false}
        policy={{ enforcing: false, allow: [], git: [{ repo: "github.com/o/a", access: "read" }] }}
        onClose={() => {}} onApplied={() => {}} />
    );
    expect(screen.queryByText(/github\.com\/o\/a/)).toBeNull();
    expect(screen.getByText(/github\.com\/o\/b/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Select all" }));
    fireEvent.click(addButton());
    await waitFor(() =>
      expect(add).toHaveBeenCalledWith("web", [{ kind: "git", target: "github.com/o/b", access: "read" }], false)
    );
  });

  it("raw-IP row is rendered but disabled and excluded from policyAddEndpoints, even under Select all", async () => {
    const add = api.policyAddEndpoints as Mock;
    const rows = [
      sum({ host: null, dest_ip: "10.0.0.1", port: 80, last_method: null, last_path: null }),
      sum({ host: "pypi.org", port: 443, last_method: "GET", last_path: "/" }),
    ];
    render(<SeedDialog name="web" rows={rows} enforcing={false} policy={bare}
      onClose={() => {}} onApplied={() => {}} />);
    expect(screen.getByText("10.0.0.1:80")).toBeInTheDocument();
    const rawIpCheckbox = screen.getByRole("checkbox", { name: "10.0.0.1:80" });
    expect(rawIpCheckbox).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Select all" }));
    expect(rawIpCheckbox).not.toBeChecked();
    expect(addButton()).toHaveTextContent("Add 1 selected to allow-list");
    fireEvent.click(addButton());
    await waitFor(() =>
      expect(add).toHaveBeenCalledWith("web", [{ kind: "http", host: "pypi.org", port: 443, access: "read" }], false)
    );
  });

  it("surfaces an error and stays open when the apply fails", async () => {
    (api.policyAddEndpoints as Mock).mockRejectedValue(new Error("daemon offline"));
    const onApplied = vi.fn();
    const onClose = vi.fn();
    render(
      <SeedDialog name="web" rows={[sum({ host: "pypi.org", port: 443, last_method: "GET", last_path: "/simple/" })]}
        policy={bare} enforcing={false} onClose={onClose} onApplied={onApplied} />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Select all" }));
    fireEvent.click(addButton());
    expect(await screen.findByRole("alert")).toHaveTextContent(/daemon offline/);
    expect(onApplied).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();
  });
});

describe("SeedDialog selection (a consent surface: nothing is approved by default)", () => {
  const rows = [
    sum({ host: "pypi.org", port: 443 }),
    sum({ host: "npmjs.org", port: 443 }),
    sum({ host: null, dest_ip: "10.0.0.1", port: 80, last_method: null, last_path: null }),
  ];

  it("opens with no candidate selected and the submit action disabled at 0", () => {
    render(<SeedDialog name="web" rows={rows} enforcing={true} policy={{ ...bare, enforcing: true }}
      onClose={() => {}} onApplied={() => {}} />);
    for (const cb of screen.getAllByRole("checkbox")) expect(cb).not.toBeChecked();
    expect(addButton()).toBeDisabled();
    expect(addButton()).toHaveTextContent("Add 0 selected to allow-list");
  });

  it("Select all / Deselect all act on every selectable candidate and the count follows", () => {
    render(<SeedDialog name="web" rows={rows} enforcing={true} policy={{ ...bare, enforcing: true }}
      onClose={() => {}} onApplied={() => {}} />);
    fireEvent.click(screen.getByRole("button", { name: "Select all" }));
    expect(screen.getByRole("checkbox", { name: "pypi.org:443" })).toBeChecked();
    expect(screen.getByRole("checkbox", { name: "npmjs.org:443" })).toBeChecked();
    expect(screen.getByRole("checkbox", { name: "10.0.0.1:80" })).not.toBeChecked();
    expect(addButton()).toBeEnabled();
    expect(addButton()).toHaveTextContent("Add 2 selected to allow-list");
    fireEvent.click(screen.getByRole("button", { name: "Deselect all" }));
    for (const cb of screen.getAllByRole("checkbox")) expect(cb).not.toBeChecked();
    expect(addButton()).toBeDisabled();
    expect(addButton()).toHaveTextContent("Add 0 selected to allow-list");
  });

  it("a single checkbox toggles its own row only and the count follows", () => {
    render(<SeedDialog name="web" rows={rows} enforcing={true} policy={{ ...bare, enforcing: true }}
      onClose={() => {}} onApplied={() => {}} />);
    fireEvent.click(screen.getByRole("checkbox", { name: "npmjs.org:443" }));
    expect(screen.getByRole("checkbox", { name: "npmjs.org:443" })).toBeChecked();
    expect(screen.getByRole("checkbox", { name: "pypi.org:443" })).not.toBeChecked();
    expect(addButton()).toHaveTextContent("Add 1 selected to allow-list");
    fireEvent.click(screen.getByRole("checkbox", { name: "npmjs.org:443" }));
    expect(addButton()).toHaveTextContent("Add 0 selected to allow-list");
  });

  it("every control is a real button or checkbox (keyboard-reachable, nothing hover-only)", () => {
    render(<SeedDialog name="web" rows={rows} enforcing={true} policy={{ ...bare, enforcing: true }}
      onClose={() => {}} onApplied={() => {}} />);
    expect(screen.getByRole("button", { name: "Select all" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Deselect all" })).toBeInTheDocument();
    expect(screen.getAllByRole("checkbox")).toHaveLength(3);
    // The dialog's rows carry no pointer-only handlers: no element relies on mouseenter.
    expect(document.querySelector("[onmouseenter]")).toBeNull();
  });
});

describe("buildCandidates", () => {
  it("orders candidates by key regardless of backend order, selectable kinds before raw IPs", () => {
    const a = sum({ host: "pypi.org", port: 443 });
    const b = sum({ host: "npmjs.org", port: 443 });
    const raw = sum({ host: null, dest_ip: "10.0.0.1", port: 80, last_method: null, last_path: null });
    const g = sum({ host: "github.com", last_method: "POST", last_path: "/o/b/git-upload-pack" });
    const keys = (rows: EndpointSummary[]) => buildCandidates(rows, bare).map((c) => c.key);
    expect(keys([raw, a, g, b])).toEqual([
      "git:github.com/o/b",
      "http:npmjs.org:443",
      "http:pypi.org:443",
      "raw-ip:10.0.0.1:80",
    ]);
    expect(keys([b, g, a, raw])).toEqual(keys([raw, a, g, b]));
  });

  it("folds rows that resolve to the same key into one candidate with summed counts, push winning", () => {
    const clone = sum({ host: "github.com", port: 443, last_method: "POST", last_path: "/o/b/git-upload-pack", allow_count: 2, deny_count: 1 });
    const push = sum({ host: "github.com", port: 80, last_method: "POST", last_path: "/o/b/git-receive-pack", allow_count: 3, deny_count: 0 });
    const out = buildCandidates([clone, push], bare);
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({ key: "git:github.com/o/b", allowCount: 5, denyCount: 1, defaultAccess: "read-write" });
    expect(out[0].label).toBe("git push → github.com/o/b");
    expect(buildCandidates([push, clone], bare)[0].label).toBe("git push → github.com/o/b");
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run (from `app/`): `npx vitest run --project=unit src/test/seedDialog.test.tsx`
Expected: FAIL — `buildCandidates` is not exported; "Select all" button not found; the default-selection test fails because every checkbox is pre-checked and the button reads "Add 2 selected…".

- [ ] **Step 3: Implement**

Replace `app/src/components/SeedDialog.tsx` from the `type CandidateKind` line through the end of the `handleAdd` function, and the footer, with:

```tsx
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
```

In the JSX, keep the header as is, then between `</DialogHeader>` and the candidate list insert the bulk controls:

```tsx
        <div className="flex items-center gap-2">
          <Button variant="ghost" size="sm" onClick={selectAll} disabled={selectable.length === 0}>
            Select all
          </Button>
          <Button variant="ghost" size="sm" onClick={deselectAll} disabled={selectedCount === 0}>
            Deselect all
          </Button>
        </div>
```

In the row render, change the checkbox `checked` prop and the count span:

```tsx
                <Checkbox
                  checked={!c.disabled && checked.has(c.key)}
                  disabled={c.disabled}
                  onCheckedChange={() => toggleChecked(c.key)}
                  aria-label={c.label}
                />
                <span className="flex-1 font-mono">{c.label}</span>
                <span className="text-xs text-muted-foreground-2">{countLabel(c)}</span>
```

And the submit button always states the count:

```tsx
          <Button
            variant="default"
            disabled={submitting || selectedCount === 0}
            onClick={() => void handleAdd()}
          >
            {`Add ${selectedCount} selected to allow-list`}
          </Button>
```

- [ ] **Step 4: Run the tests to verify they pass**

Run (from `app/`): `npx vitest run --project=unit src/test/seedDialog.test.tsx src/test/netlogView.test.tsx`
Expected: PASS (all SeedDialog suites + the untouched NetlogView suite).

- [ ] **Step 5: Gate and commit**

Run (from `app/`): `npm run lint && npm run build && npm run test`
Expected: lint clean, tsc clean, all unit + browser projects pass.

```bash
git add app/src/components/SeedDialog.tsx app/src/test/seedDialog.test.tsx
git commit -m "fix(app): review-traffic dialog selects nothing by default; deterministic, deduplicated candidate order

The dialog writes straight into the sandbox's allow-list, so pre-selecting
every candidate approved endpoints the user never looked at. Selection now
starts empty with explicit Select all / Deselect all; the submit button
always states the count and is disabled at zero. Candidates are folded by
key and sorted by key, so the list no longer follows the backend's
HashMap iteration order.

Refs #286"
```

---

### Task 2: Frozen snapshot, new-traffic notice, explicit refresh

**Files:**
- Modify: `app/src/components/SeedDialog.tsx` (state block from Task 1; header copy; a status line)
- Test: `app/src/test/seedDialog.test.tsx` (append a suite)

**Interfaces:**
- Consumes: `buildCandidates`, `Candidate` from Task 1.
- Produces: no new exports. Rendered contract the e2e (Task 3) relies on: a `role="status"` element inside the dialog whose text is `` `${n} new endpoint(s) observed since this review — refresh to include them.` `` when `n > 0` and empty otherwise; a button named `Refresh`; candidate checkboxes named by their label.

- [ ] **Step 1: Write the failing tests**

Append to `app/src/test/seedDialog.test.tsx`:

```tsx
describe("SeedDialog snapshot (a review is a frozen list, not a live feed)", () => {
  const pypi = sum({ host: "pypi.org", port: 443 });
  const npm = sum({ host: "npmjs.org", port: 443 });
  const dialog = (rows: EndpointSummary[]) => (
    <SeedDialog name="web" rows={rows} enforcing={true} policy={{ ...bare, enforcing: true }}
      onClose={() => {}} onApplied={() => {}} />
  );

  it("keeps the list and its order frozen while the rows prop changes underneath", () => {
    const { rerender } = render(dialog([pypi]));
    expect(listedLabels()).toEqual(["pypi.org:443"]);
    rerender(dialog([npm, pypi]));
    expect(listedLabels()).toEqual(["pypi.org:443"]);
    expect(screen.queryByText("npmjs.org:443")).toBeNull();
  });

  it("reports new endpoints as a non-blocking notice, distinct from the reviewed set", () => {
    const { rerender } = render(dialog([pypi]));
    expect(screen.getByRole("status")).toHaveTextContent("");
    rerender(dialog([npm, pypi]));
    expect(screen.getByRole("status")).toHaveTextContent(
      "1 new endpoint(s) observed since this review — refresh to include them.",
    );
    // The submit action is untouched by the notice.
    fireEvent.click(screen.getByRole("checkbox", { name: "pypi.org:443" }));
    expect(addButton()).toBeEnabled();
  });

  it("Refresh folds new traffic in, keeps the user's existing ticks, leaves new rows unselected", () => {
    const { rerender } = render(dialog([pypi]));
    fireEvent.click(screen.getByRole("checkbox", { name: "pypi.org:443" }));
    rerender(dialog([npm, pypi]));
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
    expect(listedLabels()).toEqual(["npmjs.org:443", "pypi.org:443"]);
    expect(screen.getByRole("checkbox", { name: "pypi.org:443" })).toBeChecked();
    expect(screen.getByRole("checkbox", { name: "npmjs.org:443" })).not.toBeChecked();
    expect(addButton()).toHaveTextContent("Add 1 selected to allow-list");
    expect(screen.getByRole("status")).toHaveTextContent("");
  });

  it("a reshuffle of the same membership neither moves rows nor raises the notice", () => {
    const { rerender } = render(dialog([npm, pypi]));
    expect(listedLabels()).toEqual(["npmjs.org:443", "pypi.org:443"]);
    rerender(dialog([pypi, npm]));
    expect(listedLabels()).toEqual(["npmjs.org:443", "pypi.org:443"]);
    expect(screen.getByRole("status")).toHaveTextContent("");
  });

  it("Refresh is available even when the snapshot was empty at open", () => {
    const { rerender } = render(dialog([]));
    expect(screen.getByText(/No new endpoints to add/)).toBeInTheDocument();
    rerender(dialog([pypi]));
    expect(screen.getByRole("status")).toHaveTextContent(/1 new endpoint/);
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
    expect(listedLabels()).toEqual(["pypi.org:443"]);
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run (from `app/`): `npx vitest run --project=unit src/test/seedDialog.test.tsx`
Expected: FAIL — the list follows the new `rows` (shows `npmjs.org:443`), no `role="status"` element, no `Refresh` button.

- [ ] **Step 3: Implement**

In `SeedDialog`, replace the `candidates` line with the snapshot block:

```tsx
  // What the netlog CURRENTLY says, recomputed on every poll the parent
  // forwards. Never rendered as the list.
  const live = useMemo(() => buildCandidates(rows, policy), [rows, policy]);

  // What the user is REVIEWING: captured once at open and only replaced by an
  // explicit Refresh. The parent keeps polling at ~1.5 s and `rows` keeps
  // changing under us; before this, the list re-derived from the live rows
  // on every poll, so membership and order moved while the user was reading
  // and a click could land on a row that had just shifted into place. A
  // consent surface has to be a stable snapshot of an explicit choice.
  const [snapshot, setSnapshot] = useState<Candidate[]>(() => live);
  const snapshotKeys = useMemo(() => new Set(snapshot.map((c) => c.key)), [snapshot]);
  const unseenCount = live.filter((c) => !snapshotKeys.has(c.key)).length;
  const refreshSnapshot = () => setSnapshot(live);

  const candidates = snapshot;
```

(`selectable`, `selectAll`, `selectedCandidates` from Task 1 keep reading `candidates`, which is now the snapshot; `checked` keys that a refresh drops out of the snapshot are simply never counted.)

Update the description copy:

```tsx
          <DialogDescription>
            Select endpoints to add to your allow-list. Already-covered entries are excluded.
            This list is a snapshot taken when the dialog opened — traffic observed since is
            reported below and only enters the list when you refresh.
          </DialogDescription>
```

Extend the bulk-controls row with the Refresh button, and add the always-present status line right after it (fixed height so the notice appearing never reflows the checkboxes):

```tsx
        <div className="flex items-center gap-2">
          <Button variant="ghost" size="sm" onClick={selectAll} disabled={selectable.length === 0}>
            Select all
          </Button>
          <Button variant="ghost" size="sm" onClick={deselectAll} disabled={selectedCount === 0}>
            Deselect all
          </Button>
          <Button variant="secondary" size="sm" className="ml-auto" onClick={refreshSnapshot}>
            Refresh
          </Button>
        </div>
        <div role="status" aria-live="polite" className="h-5 text-xs text-muted-foreground-2">
          {unseenCount > 0
            ? `${unseenCount} new endpoint(s) observed since this review — refresh to include them.`
            : ""}
        </div>
```

- [ ] **Step 4: Run the tests to verify they pass**

Run (from `app/`): `npx vitest run --project=unit src/test/seedDialog.test.tsx src/test/netlogView.test.tsx`
Expected: PASS.

- [ ] **Step 5: Gate and commit**

Run (from `app/`): `npm run lint && npm run build && npm run test`
Expected: green.

```bash
git add app/src/components/SeedDialog.tsx app/src/test/seedDialog.test.tsx
git commit -m "fix(app): freeze the review-traffic dialog into a snapshot with an explicit Refresh

The candidate list is captured once at open; the parent's netlog poll no
longer mutates it. New endpoints observed since the snapshot are counted in
a non-blocking status line and only enter the list on Refresh, which keeps
the user's existing ticks and leaves new rows unselected.

Refs #286"
```

---

### Task 3: End-to-end — the list stays frozen while live traffic keeps arriving

**Files:**
- Modify: `app/e2e/netlog.spec.ts` (append one test)

**Interfaces:**
- Consumes: `mock.setScenario({ netlog })` from `app/e2e/helpers.ts` (mutates the scenario the mock's `read_netlog` arm serves; `NetlogView` polls every 1.5 s so the change reaches the dialog within one poll); `mock.calls()` records `policy_add_endpoints:<name>:<entries.length>:<enforce>`; the `role="status"` line, the `Refresh` button and per-label checkbox names from Task 2.

- [ ] **Step 1: Write the failing test**

Append to `app/e2e/netlog.spec.ts` inside `test.describe("netlog", …)`:

```ts
  test("the review dialog is a frozen snapshot while live traffic keeps arriving, driven by keyboard", async ({ page, mock }) => {
    await page.getByText("ubuntu:24.04").click();
    await page.getByRole("tab", { name: "Netlog" }).click();
    await expect.poll(() => mock.calls()).toContain("read_netlog:web");
    await page.getByRole("button", { name: "Review observed traffic" }).click();
    const dialog = page.getByRole("dialog");
    await expect(dialog).toBeVisible();

    // Snapshot at open: github.com:443 selectable, the raw IP listed but disabled,
    // nothing ticked, submit disabled at 0.
    const github = dialog.getByRole("checkbox", { name: "github.com:443" });
    await expect(github).toBeVisible();
    await expect(github).not.toBeChecked();
    await expect(dialog.getByRole("checkbox", { name: "10.0.0.9:22" })).toBeDisabled();
    const add = dialog.getByRole("button", { name: /^Add \d+ selected to allow-list$/ });
    await expect(add).toHaveText("Add 0 selected to allow-list");
    await expect(add).toBeDisabled();

    // Live traffic arrives underneath the open dialog: a brand-new endpoint,
    // and the existing ones re-timestamped so the backend order would flip.
    await mock.setScenario({
      netlog: [
        {
          host: "pypi.org",
          dest_ip: "151.101.0.223",
          port: 443,
          tier: "l7",
          verdict: "allow",
          allow_count: 1,
          deny_count: 0,
          first_seen_ms: 3000,
          last_seen_ms: 3000,
          last_method: "GET",
          last_path: "/simple/",
        },
        ...netlogEntries.map((e) => ({ ...e, last_seen_ms: e.last_seen_ms + 5000 })),
      ],
    });
    // The poll delivered it (the notice proves the data reached the dialog)…
    await expect(dialog.getByRole("status")).toHaveText(
      "1 new endpoint(s) observed since this review — refresh to include them.",
      { timeout: 10_000 },
    );
    // …yet the reviewed list is unchanged: same membership, same order.
    await expect(dialog.getByRole("checkbox", { name: "pypi.org:443" })).toHaveCount(0);
    await expect(dialog.getByRole("checkbox")).toHaveCount(2); // still exactly two rows
    await expect(dialog.getByRole("checkbox").first()).toHaveAccessibleName("github.com:443");

    // Keyboard only from here: tick github.com via Space, refresh via Enter.
    await github.focus();
    await page.keyboard.press("Space");
    await expect(github).toBeChecked();
    await expect(add).toHaveText("Add 1 selected to allow-list");
    await dialog.getByRole("button", { name: "Refresh" }).focus();
    await page.keyboard.press("Enter");
    // Sorted by key: github < pypi < raw-ip. Existing tick kept, new row untouched.
    await expect(dialog.getByRole("checkbox")).toHaveCount(3);
    await expect(dialog.getByRole("checkbox").nth(0)).toHaveAccessibleName("github.com:443");
    await expect(dialog.getByRole("checkbox").nth(1)).toHaveAccessibleName("pypi.org:443");
    await expect(dialog.getByRole("checkbox").nth(2)).toHaveAccessibleName("10.0.0.9:22");
    await expect(github).toBeChecked();
    await expect(dialog.getByRole("checkbox", { name: "pypi.org:443" })).not.toBeChecked();
    await expect(dialog.getByRole("status")).toHaveText("");
    await expect(add).toHaveText("Add 1 selected to allow-list");

    await add.focus();
    await page.keyboard.press("Enter");
    await expect.poll(() => mock.calls()).toContain("policy_add_endpoints:web:1:false");
    await expect(dialog).toHaveCount(0);
  });
```

- [ ] **Step 2: Run the e2e**

This task runs AFTER Task 2, so the product side is already fixed; the test's guard is the `toHaveCount(0)` on `pypi.org:443` AFTER the notice has appeared — exactly the assertion the old live-updating dialog violated (the poll would have injected the row). Do not stash or revert to watch it fail; run the spec as written:

Run (from `app/`): `npx playwright test e2e/netlog.spec.ts --project=chromium`
Expected: PASS on the Task-2 tree. If it fails, the failure is in the test itself (a selector or timing), not the product — fix the test, do not touch the component.

- [ ] **Step 3: Run on webkit too when the browser is installed**

Run (from `app/`): `npx playwright test e2e/netlog.spec.ts --project=webkit`
Expected: PASS, or a `browserType.launch: Executable doesn't exist` error meaning webkit is not installed locally (CI's Linux job installs it via `npm run e2e:install`; in that case rely on CI).

- [ ] **Step 4: Gate and commit**

Run (from `app/`): `npm run lint && npm run build`
Expected: lint clean (the e2e dir is linted too).

```bash
git add app/e2e/netlog.spec.ts
git commit -m "test(app): e2e — review dialog stays frozen while the netlog keeps changing underneath

Mutates the mock scenario while the dialog is open, waits for the poll to
land (the new-traffic notice proves it did), and asserts the reviewed list
kept its membership and order. Drives the tick, Refresh and Add entirely
by keyboard.

Refs #286"
```

---

### Task 4: Full app gate + parity checks

**Files:** none new.

- [ ] **Step 1: Run the complete App CI equivalent**

Run (from `app/`): `npm run lint && npm run build && npm run test && npx playwright test --project=chromium`
Expected: all green, including `src/test/tauriMockParity.test.ts` (no IPC surface changed) and every other e2e spec (the dialog is only reachable from the Netlog tab; nothing else should move).

- [ ] **Step 2: Backend gate is unaffected — confirm with a grep, not a build**

Run: `git diff main --stat -- app/src-tauri crates`
Expected: empty. No Rust changed; the six workspace gates and the `app/src-tauri` gate are unaffected by construction.

- [ ] **Step 3: Nothing to commit** — this task is verification only.

---

## Self-review

- Spec coverage: AC1 (frozen list/order) → Task 2 + Task 3; AC2 (explicit refresh) → Task 2; AC3 (nothing pre-selected) → Task 1; AC4 (Select all / Deselect all) → Task 1; AC5 (disabled at 0, count in label) → Task 1; AC6 (non-blocking notice, neither added nor dropped) → Task 2; AC7 (no hover/pointer dependence) → Task 1 structural test + Task 3 keyboard driving; AC8 (tests: stability, default-empty, select/deselect, e2e with live-mutating traffic) → Tasks 1–3. Deterministic ordering (In Scope) → Task 1 `byKey`.
- Placeholders: none.
- Type consistency: `Candidate` fields `allowCount`/`denyCount` (Task 1) are what `countLabel` and the dedupe test read; `buildCandidates(rows, policy)` signature is shared by Tasks 1–2; `role="status"` text and the `Refresh` name are identical between Task 2's implementation, its unit tests, and Task 3's e2e.
