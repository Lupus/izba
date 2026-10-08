# Policy Editor Accessible Names Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give every editable control in the desktop app's policy editor a distinct, row-identifying accessible name, so each host rule and git rule is unambiguous in the accessibility tree (GitHub issue #244).

**Architecture:** One naming scheme, `ruleName(kind, value, index)` → `"host rule 1 (api.x.com)"` / `"git rule 2 (empty)"`, is the only source of row identity. Each host row renders one visually-hidden `for <rule>` span; the visible `Host`/`Ports`/`Access` labels are tied to their controls through `htmlFor` + `aria-labelledby="<visible-label-id> <rule-span-id>"`, so the accessible name is literally the visible text followed by the rule (`"Host for host rule 1 (api.x.com)"`). Composite controls become labelled groups: `PortEditor` a `role="group"`, `AccessPicker` the `role="radiogroup"` Radix already renders for a single-select ToggleGroup. Git rows (which have no visible labels, and must not gain any — appearance is frozen) use `aria-label` strings built from the same `ruleName`. Row cards become `role="group"` named by the rule, and every remove/add-port control names the rule it acts on.

**Tech Stack:** React 18 + TypeScript (Tauri 2 front-end in `app/`), Radix `ToggleGroup`, Tailwind (`sr-only`), Vitest + Testing Library (jsdom `unit` project).

**Spec:** GitHub issue #244 — https://github.com/Lupus/izba/issues/244 (body is the spec; this plan quotes its Acceptance Criteria).

## Global Constraints

- Branch: `fix/policy-editor-accessible-names` (already created from `origin/main`). Commit messages are Conventional Commits with `Refs #244` in the body; never push to `main`.
- **Appearance unchanged** (AC 7): no new visible text, no class changes on visible elements, no layout change. A `<label>` swapped for a `<span>` must keep the identical `className`. Hidden text is rendered with the `hidden` attribute and read only through `aria-labelledby` — NOT `sr-only`, which is `position:absolute` and, with no positioned ancestor inside the scroll pane, extends the document's scroll height.
- **No change to policy semantics, the `policy.yaml` shape, or the daemon RPCs** (issue Out of Scope). `api.policySetFull` call shapes in the existing tests must stay byte-identical.
- The `#239` behaviour (Host lock on a pinned row, Access-widening refusal, `aria-describedby` passthrough notice) must keep passing untouched.
- `AccessPicker`'s default accessible name stays `"access"` when no override is passed — `SeedDialog.tsx` relies on that and is out of scope.
- No new npm dependencies.
- Every gate must be green before each commit: `npm run lint`, `npm run build`, `npx vitest run --project=unit` (all run from `app/`; `node_modules` is already installed in this worktree).
- Do not touch `hack/dogfood/`, `app/e2e/`, or `app/src-tauri/` — no IPC command changes, so `tauriMockParity` is unaffected.

## Review Focus

1. **Two rows with the same host value** (e.g. both `api.x.com`): every control's name must still differ (ordinal carries the distinction). Pinned by Task 2's "colliding values" test.
2. **Two freshly-added empty rows**: both must read `… (empty)` with different ordinals, and typing into one must rename only that row. Pinned by Task 2's "colliding values" test.
3. **Two rows sharing a port** (both `443`): the chip remove buttons must be distinguishable AND clicking one must remove the port from *its* row only. Pinned by Task 2's "remove buttons" test (asserts the `policySetFull` payload after the click).
4. **Row removal renumbers**: after removing rule 1, the former rule 2 becomes rule 1 — the names are live, not frozen at mount. Pinned by Task 2's "renumbers after removal" test.
5. **Host value with surrounding whitespace**: the name uses the trimmed value (so `" api.x.com "` reads as `api.x.com`, matching what Save will persist), and a whitespace-only host reads as `(empty)`. Pinned by Task 2's "colliding values" test (whitespace-only case).

---

### Task 1: Primitives — `SegmentedControl`/`AccessPicker` accept `aria-labelledby`; `EditableList` can name each row as a group

**Files:**
- Modify: `app/src/components/ui/segmented-control.tsx`
- Modify: `app/src/components/AccessPicker.tsx`
- Modify: `app/src/components/ui/editable-list.tsx`
- Test: `app/src/test/ui/segmentedControl.test.tsx`
- Test: `app/src/test/ui/editableList.test.tsx`
- Test (new): `app/src/test/accessPicker.test.tsx`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces:
  - `SegmentedControlProps<T>`: `"aria-label"?: string; "aria-labelledby"?: string;` (both optional; both forwarded to `ToggleGroup.Root`).
  - `AccessPicker` props: `{ value: Access; onChange: (v: Access) => void; "aria-label"?: string; "aria-labelledby"?: string }`. When neither is given it renders `aria-label="access"` (unchanged default). When `aria-labelledby` is given, no `aria-label` is rendered.
  - `EditableListProps<T>`: new optional `rowLabel?: (item: T, index: number) => string;`. When given, each row wrapper (the `RowCard` in `card` density, the wrapper `div` in `inline` density) gets `role="group"` and `aria-label={rowLabel(item, i)}`. When absent, markup is byte-identical to today.

- [ ] **Step 1: Write the failing tests**

Append to `app/src/test/ui/segmentedControl.test.tsx` inside the existing `describe`:

```tsx
  it("can be named by aria-labelledby instead of aria-label", () => {
    render(
      <>
        <span id="row-name">Access for host rule 1 (api.x.com)</span>
        <SegmentedControl aria-labelledby="row-name" value="read" onChange={() => {}} options={opts} />
      </>,
    );
    const group = screen.getByRole("radiogroup", { name: "Access for host rule 1 (api.x.com)" });
    expect(group).not.toHaveAttribute("aria-label");
  });
```

Create `app/src/test/accessPicker.test.tsx`:

```tsx
import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { AccessPicker } from "../components/AccessPicker";

describe("AccessPicker", () => {
  it("defaults its accessible name to 'access' (SeedDialog relies on this)", () => {
    render(<AccessPicker value="read" onChange={() => {}} />);
    expect(screen.getByRole("radiogroup", { name: "access" })).toBeInTheDocument();
  });

  it("takes an aria-label override", () => {
    render(<AccessPicker value="read" onChange={() => {}} aria-label="Access for git rule 1 (github.com/o/a)" />);
    expect(screen.getByRole("radiogroup", { name: "Access for git rule 1 (github.com/o/a)" })).toBeInTheDocument();
    expect(screen.queryByRole("radiogroup", { name: "access" })).not.toBeInTheDocument();
  });

  it("takes aria-labelledby, and then renders no aria-label at all", () => {
    render(
      <>
        <span id="lbl">Access</span>
        <span id="rule">for host rule 2 (db.internal)</span>
        <AccessPicker value="read-write" onChange={() => {}} aria-labelledby="lbl rule" />
      </>,
    );
    const group = screen.getByRole("radiogroup", { name: "Access for host rule 2 (db.internal)" });
    expect(group).not.toHaveAttribute("aria-label");
  });
});
```

Append to `app/src/test/ui/editableList.test.tsx` inside the existing `describe`:

```tsx
  it("names each row as a group when rowLabel is given, in both densities", () => {
    const { rerender } = render(
      <EditableList
        items={["api.x.com", "db.internal"]}
        renderRow={(item) => <span>row-{item}</span>}
        onAdd={() => {}}
        onRemove={() => {}}
        addLabel="Add"
        emptyHint="none"
        density="card"
        rowLabel={(item, i) => `host rule ${i + 1} (${item})`}
      />,
    );
    const first = screen.getByRole("group", { name: "host rule 1 (api.x.com)" });
    expect(first).toContainElement(screen.getByText("row-api.x.com"));
    expect(screen.getByRole("group", { name: "host rule 2 (db.internal)" })).toBeInTheDocument();
    rerender(
      <EditableList
        items={["api.x.com"]}
        renderRow={(item) => <span>row-{item}</span>}
        onAdd={() => {}}
        onRemove={() => {}}
        addLabel="Add"
        emptyHint="none"
        density="inline"
        rowLabel={(item, i) => `host rule ${i + 1} (${item})`}
      />,
    );
    expect(screen.getByRole("group", { name: "host rule 1 (api.x.com)" })).toBeInTheDocument();
  });

  it("renders no group role when rowLabel is absent (markup unchanged for other callers)", () => {
    render(
      <EditableList items={["a"]} renderRow={() => <span>x</span>} onAdd={() => {}}
        onRemove={() => {}} addLabel="Add" emptyHint="none" density="card" />,
    );
    expect(screen.queryByRole("group")).not.toBeInTheDocument();
  });
```

- [ ] **Step 2: Run the tests to verify they fail**

Run (from `app/`): `npx vitest run --project=unit src/test/ui/segmentedControl.test.tsx src/test/accessPicker.test.tsx src/test/ui/editableList.test.tsx`

Expected: the three new `aria-labelledby`/`rowLabel` tests FAIL (TypeScript prop errors surface as test failures under Vitest's esbuild transform only at runtime — the `getByRole` lookups fail with "Unable to find an accessible element with the role "group" and name …"). The "defaults to 'access'" and "no group role when absent" tests PASS already — that is expected; they are guards.

- [ ] **Step 3: Implement**

`app/src/components/ui/segmented-control.tsx` — replace the props interface and the `Root` props:

```tsx
export interface SegmentedControlProps<T extends string> {
  value: T;
  onChange: (value: T) => void;
  options: SegmentedOption<T>[];
  /** Accessible name of the group. Pass exactly one of these: a literal
   *  `aria-label`, or `aria-labelledby` (space-separated element ids —
   *  the name is the referenced elements' text, concatenated in order). */
  "aria-label"?: string;
  "aria-labelledby"?: string;
  className?: string;
}
```

and in the JSX:

```tsx
    <ToggleGroup.Root
      type="single"
      value={value}
      onValueChange={(v) => v && onChange(v as T)}
      aria-label={aria["aria-label"]}
      aria-labelledby={aria["aria-labelledby"]}
      className={cn("inline-flex gap-1 rounded-lg border border-input p-0.5", className)}
    >
```

(React omits an attribute whose value is `undefined`, so a caller passing only one of the two renders only that one.)

`app/src/components/AccessPicker.tsx` — full new content:

```tsx
import type { Access } from "../lib/types";
import { SegmentedControl } from "@/components/ui/segmented-control";

/** The read / read-write segmented control. Its accessible name defaults to
 *  "access" (SeedDialog renders one per candidate inside a row that is itself
 *  the label). A caller whose rows need to be told apart — PolicyEditor, #244
 *  — names it by the rule it belongs to, either with an `aria-label` string or
 *  with `aria-labelledby` ids; when `aria-labelledby` is given no `aria-label`
 *  is rendered, so the two never compete for the name. */
export function AccessPicker({
  value,
  onChange,
  ...aria
}: {
  value: Access;
  onChange: (v: Access) => void;
  "aria-label"?: string;
  "aria-labelledby"?: string;
}) {
  const labelledby = aria["aria-labelledby"];
  const label = labelledby ? undefined : (aria["aria-label"] ?? "access");
  return (
    <SegmentedControl<Access>
      aria-label={label}
      aria-labelledby={labelledby}
      value={value}
      onChange={onChange}
      options={[
        { value: "read", label: "read" },
        { value: "read-write", label: "read-write" },
      ]}
    />
  );
}
```

`app/src/components/ui/editable-list.tsx` — add the prop and apply it. In `EditableListProps<T>` add after `rowAriaLabel`:

```tsx
  /** When given, each row is a labelled `role="group"` named by this — so a
   *  screen reader (and the dogfood driver's set-of-marks) can tell rows
   *  apart as units, not only by their individual controls (#244). Absent ⇒
   *  no group role, markup identical to before. */
  rowLabel?: (item: T, index: number) => string;
```

Destructure `rowLabel` in the component signature, then add next to `const label = …`:

```tsx
  const groupProps = (item: T, i: number) =>
    rowLabel ? { role: "group" as const, "aria-label": rowLabel(item, i) } : {};
```

and spread it onto both row wrappers:

```tsx
              <RowCard key={i} className="items-start p-3" {...groupProps(item, i)}>
```

```tsx
              <div key={i} className="flex flex-wrap items-center gap-2" {...groupProps(item, i)}>
```

`RowCard` (`app/src/components/ui/row-editor.tsx`) does not forward extra props today, so extend it:

```tsx
export function RowCard({
  children,
  className,
  ...rest
}: { children: React.ReactNode; className?: string } & React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={cn("flex items-center gap-2 rounded-lg border border-border p-2", className)} {...rest}>
      {children}
    </div>
  );
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run (from `app/`): `npx vitest run --project=unit src/test/ui/segmentedControl.test.tsx src/test/accessPicker.test.tsx src/test/ui/editableList.test.tsx src/test/ui/rowEditor.test.tsx src/test/seedDialog.test.tsx`

Expected: all PASS (including the untouched SeedDialog and rowEditor suites — `seedDialog.test.tsx` may be named slightly differently; run `ls src/test | grep -i seed` and use that file).

- [ ] **Step 5: Lint and commit**

Run (from `app/`): `npm run lint && npx tsc --noEmit`

Expected: clean. Then:

```bash
git add app/src/components/ui/segmented-control.tsx app/src/components/AccessPicker.tsx \
        app/src/components/ui/editable-list.tsx app/src/components/ui/row-editor.tsx \
        app/src/test/ui/segmentedControl.test.tsx app/src/test/accessPicker.test.tsx \
        app/src/test/ui/editableList.test.tsx
git diff --cached --stat
git commit -m "feat(app): let SegmentedControl/AccessPicker take aria-labelledby and EditableList name rows as groups

Groundwork for #244: the policy editor needs to name each row's
Access control by the rule it belongs to (via the visible label +
a hidden rule descriptor), and to expose each rule as a labelled
group. Defaults are unchanged — AccessPicker still reads \"access\"
when nothing is passed (SeedDialog), and EditableList renders no
group role unless rowLabel is given.

Refs #244"
```

(Use `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>` as the final trailer line of every commit, after a blank line.)

---

### Task 2: `PolicyEditor` — name every control by its rule

**Files:**
- Modify: `app/src/components/PolicyEditor.tsx` (the `PortEditor` component ~lines 201–306, the host `renderRow` ~lines 599–658, the git `renderRow` ~lines 666–688)
- Test: `app/src/test/policyEditor.test.tsx` (new `describe` block + selector updates in existing tests)

**Interfaces:**
- Consumes (from Task 1): `AccessPicker`'s `aria-label` / `aria-labelledby` props; `EditableList`'s `rowLabel` prop.
- Produces (the naming contract tests and the dogfood driver will see):
  - Row group: `"host rule N (<host>)"` / `"git rule N (<target>)"`, where `N` is the 1-based position and the value is trimmed, or `empty` when blank.
  - Host input: `"Host for host rule N (<host>)"` (a `<label htmlFor>` carrying the visible `Host` text, plus `aria-labelledby`).
  - Ports group: `"Ports for host rule N (<host>)"`; its add field and Add button: `"Add port to host rule N (<host>)"` (textbox and button roles respectively); each chip's remove: `"Remove port <p> from host rule N (<host>)"`.
  - Access group (host row): `"Access for host rule N (<host>)"`.
  - Git target input: `"Repo for git rule N (<target>)"`; git Access group: `"Access for git rule N (<target>)"`.
  - Row remove buttons: `"Remove host rule N (<host>)"` / `"Remove git rule N (<target>)"`.

- [ ] **Step 1: Write the failing tests**

Append a new `describe` at the end of `app/src/test/policyEditor.test.tsx` (the file already imports `render, screen, fireEvent, waitFor, within`, `Mock`, `api`, `PolicyEditor`):

```tsx
describe("PolicyEditor accessible names (#244)", () => {
  it("names each host row's Host, Ports and Access by the rule they belong to", async () => {
    (api.policyShow as Mock).mockResolvedValue({
      enforcing: true,
      allow: [
        { host: "api.x.com", ports: [443], access: "read-write" },
        { host: "db.internal", ports: [5432], access: "read" },
      ],
      git: [],
    });
    render(<PolicyEditor name="web" />);
    const host1 = await screen.findByRole("textbox", { name: "Host for host rule 1 (api.x.com)" });
    const host2 = screen.getByRole("textbox", { name: "Host for host rule 2 (db.internal)" });
    expect(host1).toHaveValue("api.x.com");
    expect(host2).toHaveValue("db.internal");
    const row1 = screen.getByRole("group", { name: "host rule 1 (api.x.com)" });
    const row2 = screen.getByRole("group", { name: "host rule 2 (db.internal)" });
    expect(row1).toContainElement(host1);
    expect(row2).toContainElement(host2);
    expect(within(row1).getByRole("group", { name: "Ports for host rule 1 (api.x.com)" })).toBeInTheDocument();
    expect(within(row2).getByRole("group", { name: "Ports for host rule 2 (db.internal)" })).toBeInTheDocument();
    const access1 = within(row1).getByRole("radiogroup", { name: "Access for host rule 1 (api.x.com)" });
    const access2 = within(row2).getByRole("radiogroup", { name: "Access for host rule 2 (db.internal)" });
    expect(within(access1).getByRole("radio", { name: "read-write" })).toHaveAttribute("data-state", "on");
    expect(within(access2).getByRole("radio", { name: "read" })).toHaveAttribute("data-state", "on");
    expect(screen.getByRole("textbox", { name: "Add port to host rule 1 (api.x.com)" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Add port to host rule 2 (db.internal)" })).toBeInTheDocument();
  });

  it("associates the visible Host label with its input, and the name starts with that text", async () => {
    render(<PolicyEditor name="web" />); // default mock: api.x.com + db.internal
    const input = await screen.findByRole("textbox", { name: "Host for host rule 1 (api.x.com)" });
    const labels = screen.getAllByText("Host").filter((el) => el.tagName === "LABEL") as HTMLLabelElement[];
    const label = labels.find((l) => l.control === input);
    expect(label).toBeDefined();
    expect(label?.htmlFor).toBe(input.id);
    expect(input.id).not.toBe("");
    // The visible "Ports" / "Access" labels are referenced by their groups.
    const row1 = screen.getByRole("group", { name: "host rule 1 (api.x.com)" });
    const ports = within(row1).getByRole("group", { name: "Ports for host rule 1 (api.x.com)" });
    const portsLabelIds = (ports.getAttribute("aria-labelledby") ?? "").split(" ");
    expect(portsLabelIds.map((id) => document.getElementById(id)?.textContent)).toEqual([
      "Ports",
      "for host rule 1 (api.x.com)",
    ]);
    const access = within(row1).getByRole("radiogroup", { name: "Access for host rule 1 (api.x.com)" });
    const accessLabelIds = (access.getAttribute("aria-labelledby") ?? "").split(" ");
    expect(accessLabelIds.map((id) => document.getElementById(id)?.textContent)).toEqual([
      "Access",
      "for host rule 1 (api.x.com)",
    ]);
  });

  it("names git rows by their target, not the placeholder", async () => {
    (api.policyShow as Mock).mockResolvedValue({
      enforcing: true,
      allow: [],
      git: [
        { repo: "github.com/o/a", access: "read" },
        { host: "gitlab.com", access: "read-write" },
      ],
    });
    render(<PolicyEditor name="web" />);
    const repo1 = await screen.findByRole("textbox", { name: "Repo for git rule 1 (github.com/o/a)" });
    expect(repo1).toHaveValue("github.com/o/a");
    expect(screen.getByRole("textbox", { name: "Repo for git rule 2 (gitlab.com)" })).toHaveValue("gitlab.com");
    expect(screen.queryByRole("textbox", { name: "github.com/owner/repo" })).not.toBeInTheDocument();
    const row2 = screen.getByRole("group", { name: "git rule 2 (gitlab.com)" });
    expect(within(row2).getByRole("radiogroup", { name: "Access for git rule 2 (gitlab.com)" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Remove git rule 1 (github.com/o/a)" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Remove git rule 2 (gitlab.com)" })).toBeInTheDocument();
    // A freshly added git row reads as empty, with its own ordinal.
    fireEvent.click(screen.getByRole("button", { name: /Add repo/ }));
    expect(screen.getByRole("textbox", { name: "Repo for git rule 3 (empty)" })).toHaveValue("");
  });

  it("names remove buttons by the rule, and port chips by rule even when ports collide", async () => {
    (api.policyShow as Mock).mockResolvedValue({
      enforcing: true,
      allow: [
        { host: "api.x.com", ports: [443], access: "read-write" },
        { host: "db.internal", ports: [443], access: "read-write" },
      ],
      git: [],
    });
    render(<PolicyEditor name="web" />);
    await screen.findByDisplayValue("api.x.com");
    expect(screen.getByRole("button", { name: "Remove host rule 1 (api.x.com)" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Remove host rule 2 (db.internal)" })).toBeInTheDocument();
    // Same port on both rows: getByRole proves each chip name is unique.
    const chip1 = screen.getByRole("button", { name: "Remove port 443 from host rule 1 (api.x.com)" });
    screen.getByRole("button", { name: "Remove port 443 from host rule 2 (db.internal)" });
    fireEvent.click(chip1);
    fireEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() =>
      expect(api.policySetFull).toHaveBeenCalledWith(
        "web",
        [
          { host: "api.x.com", ports: [], access: "read-write" },
          { host: "db.internal", ports: [443], access: "read-write" },
        ],
        [],
      ),
    );
  });

  it("keeps names distinct when two rows share a host value or are empty, and follows edits", async () => {
    (api.policyShow as Mock).mockResolvedValue({
      enforcing: true,
      allow: [
        { host: "api.x.com", ports: [443] },
        { host: "api.x.com", ports: [443] },
      ],
      git: [],
    });
    render(<PolicyEditor name="web" />);
    await screen.findByDisplayValue("api.x.com");
    // Duplicate values: the ordinal keeps them apart (getByRole throws on >1 match).
    screen.getByRole("textbox", { name: "Host for host rule 1 (api.x.com)" });
    screen.getByRole("textbox", { name: "Host for host rule 2 (api.x.com)" });
    screen.getByRole("button", { name: "Remove port 443 from host rule 1 (api.x.com)" });
    screen.getByRole("button", { name: "Remove port 443 from host rule 2 (api.x.com)" });
    // Two new empty rows: distinct too.
    fireEvent.click(screen.getByRole("button", { name: /Add host/ }));
    fireEvent.click(screen.getByRole("button", { name: /Add host/ }));
    const row3 = screen.getByRole("textbox", { name: "Host for host rule 3 (empty)" });
    screen.getByRole("textbox", { name: "Host for host rule 4 (empty)" });
    screen.getByRole("group", { name: "host rule 3 (empty)" });
    screen.getByRole("button", { name: "Remove host rule 4 (empty)" });
    // The name is live: typing renames that row only, trimmed; whitespace-only stays empty.
    fireEvent.change(row3, { target: { value: "  new.example.com  " } });
    expect(screen.getByRole("textbox", { name: "Host for host rule 3 (new.example.com)" })).toBe(row3);
    screen.getByRole("textbox", { name: "Host for host rule 4 (empty)" });
    fireEvent.change(row3, { target: { value: "   " } });
    expect(screen.getByRole("textbox", { name: "Host for host rule 3 (empty)" })).toBe(row3);
  });

  it("renumbers the remaining rows after a removal", async () => {
    render(<PolicyEditor name="web" />); // default mock: api.x.com + db.internal
    await screen.findByRole("textbox", { name: "Host for host rule 2 (db.internal)" });
    fireEvent.click(screen.getByRole("button", { name: "Remove host rule 1 (api.x.com)" }));
    expect(screen.getByRole("textbox", { name: "Host for host rule 1 (db.internal)" })).toHaveValue("db.internal");
    expect(screen.queryByRole("textbox", { name: "Host for host rule 2 (db.internal)" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Remove host rule 1 (db.internal)" })).toBeInTheDocument();
  });

  it("keeps the pinned-row Host lock and its passthrough notice wired to the renamed input", async () => {
    (api.policyShow as Mock).mockResolvedValue({
      enforcing: true,
      allow: [{ host: "pinned.vendor.com", ports: [{ port: 443, protocol: "tcp" }], access: "read-write" }],
      git: [],
    });
    render(<PolicyEditor name="web" />);
    const input = await screen.findByRole("textbox", { name: "Host for host rule 1 (pinned.vendor.com)" });
    expect(input).toHaveAttribute("readonly");
    const noticeId = input.getAttribute("aria-describedby");
    expect(noticeId).toBeTruthy();
    expect(document.getElementById(noticeId!)?.textContent).toMatch(/TLS-pinning passthrough/);
    fireEvent.change(input, { target: { value: "elsewhere.example.com" } });
    expect(input).toHaveValue("pinned.vendor.com");
  });
});
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run (from `app/`): `npx vitest run --project=unit src/test/policyEditor.test.tsx -t "#244"`

Expected: all 7 FAIL with "Unable to find an accessible element with the role … and name …" (the controls are still named `add port`, `access`, by placeholder, or by position).

- [ ] **Step 3: Implement the naming in `PolicyEditor.tsx`**

3a. Add the single naming helper next to `gitRuleTarget` (top of the file, after the `GitRow` interface):

```tsx
/** The ONE row-identifying descriptor every control in a rule's row is
 *  named by (#244): `host rule 3 (api.x.com)` / `git rule 1 (github.com/o/a)`.
 *  Ordinal + value, always both: the value says WHICH rule a screen-reader
 *  user (or the dogfood driver's set-of-marks) is on, and the ordinal keeps
 *  two rows with the same value — or two still-empty rows — from ever
 *  sharing a name. The value is trimmed, as Save will persist it; a blank
 *  row reads `(empty)`. The name is live — it follows edits and renumbers
 *  on removal — which is the point: it describes the rule as it is now. */
function ruleName(kind: "host" | "git", value: string, index: number): string {
  const v = value.trim();
  return `${kind} rule ${index + 1} (${v === "" ? "empty" : v})`;
}
```

3b. `PortEditor`: add two props and name its controls. New signature:

```tsx
function PortEditor({
  ports,
  access,
  enforcing,
  rule,
  labelledBy,
  onAdd,
  onRemove,
}: {
  ports: PortRow[];
  access: Access;
  enforcing: boolean;
  /** The row descriptor from `ruleName` — every control in here names the
   *  rule it acts on, so two rows sharing a port (or a blank add field) are
   *  never announced identically (#244). */
  rule: string;
  /** Space-separated ids for this group's `aria-labelledby`: the visible
   *  "Ports" label, then the row's hidden `for <rule>` span. */
  labelledBy: string;
  onAdd: (port: number) => void;
  onRemove: (port: number) => void;
}) {
```

(keep the two existing explanatory comments on `access` / `enforcing`). Change the root element and the three controls:

```tsx
    <div role="group" aria-labelledby={labelledBy} className="flex flex-1 flex-col gap-1">
```

```tsx
              <Button
                type="button"
                variant="ghost"
                size="icon"
                aria-label={`Remove port ${p.port} from ${rule}`}
                onClick={() => onRemove(p.port)}
                className="h-3.5 w-3.5 p-0 text-muted-foreground-2 hover:text-destructive"
              >
```

```tsx
          placeholder="add port"
          aria-label={`Add port to ${rule}`}
          inputMode="numeric"
```

```tsx
        <Button
          type="button"
          variant="secondary"
          size="sm"
          aria-label={`Add port to ${rule}`}
          onClick={commit}
        >
          Add
        </Button>
```

3c. Host rows. Replace the body of the hosts `renderRow` (from `const pinned = pinnedPorts(r);` through the closing `</>`), keeping every existing attribute and comment on the Input/notice, with:

```tsx
                renderRow={(r, i) => {
                  const pinned = pinnedPorts(r);
                  const locked = pinned.length > 0;
                  // Namespaced by instanceId (useId) AND per-row by index, so
                  // aria-describedby / aria-labelledby resolve the right
                  // element even with several rows in this instance, or two
                  // mounted instances of PolicyEditor.
                  const rowId = `${instanceId}-host-${i}`;
                  const noticeId = `${rowId}-passthrough-notice`;
                  // #244: one hidden "for <rule>" span per row; each visible
                  // field label is referenced FIRST, so the accessible name
                  // is the visible text followed by the rule — "Host for
                  // host rule 1 (api.x.com)" — and a label edit can never
                  // drift from the name.
                  const rule = ruleName("host", r.host, i);
                  // Two hidden spans: the value-bearing Host input is named by the ORDINAL only
                  // (its name must not change per keystroke); Ports/Access use ordinal + value.
                  const ordinalId = `${rowId}-ordinal`;
                  const valueId = `${rowId}-value`;
                  const hostLabelId = `${rowId}-host-label`;
                  const hostInputId = `${rowId}-host`;
                  const portsLabelId = `${rowId}-ports-label`;
                  const accessLabelId = `${rowId}-access-label`;
                  return (
                    <>
                      <span id={ordinalId} hidden>for {ruleOrdinal("host", i)}</span>
                      <span id={valueId} hidden>{ruleValue(r.host)}</span>
                      <div className="flex w-full items-center gap-2">
                        <label
                          id={hostLabelId}
                          htmlFor={hostInputId}
                          className="w-12 shrink-0 text-xs font-semibold text-muted-foreground"
                        >
                          Host
                        </label>
                        <Input
                          id={hostInputId}
                          aria-labelledby={`${hostLabelId} ${ordinalId}`}
                          value={r.host}
                          onChange={(e) => setHost(i, e.target.value)}
                          placeholder="api.example.com or *.example.com"
                          className="flex-1 font-mono text-sm"
                          readOnly={locked}
                          aria-describedby={locked ? noticeId : undefined}
                          title={
                            locked
                              ? `Locked: this row carries a TLS-pinning passthrough port — ${PIN_ESCAPE_HINT}.`
                              : undefined
                          }
                        />
                      </div>
                      {locked && (
                        <p
                          id={noticeId}
                          className="w-full rounded-md border border-destructive/30 bg-destructive/10 px-2 py-1.5 text-xs text-destructive"
                        >
                          {passthroughNotice(pinned, r.access, enforcing)}
                        </p>
                      )}
                      <div className="flex w-full items-center gap-2">
                        {/* A span, not a <label>: a label can only target a
                            labelable element, and the ports control is a
                            group — it is named through aria-labelledby. */}
                        <span id={portsLabelId} className="w-12 shrink-0 text-xs font-semibold text-muted-foreground">
                          Ports
                        </span>
                        <PortEditor
                          ports={r.ports}
                          access={r.access}
                          enforcing={enforcing}
                          rule={rule}
                          labelledBy={`${portsLabelId} ${ordinalId} ${valueId}`}
                          onAdd={(p) => addPort(i, p)}
                          onRemove={(p) => removePort(i, p)}
                        />
                      </div>
                      <div className="flex w-full items-center gap-2">
                        <span id={accessLabelId} className="w-12 shrink-0 text-xs font-semibold text-muted-foreground">
                          Access
                        </span>
                        <AccessPicker
                          aria-labelledby={`${accessLabelId} ${ordinalId} ${valueId}`}
                          value={r.access}
                          onChange={(v) => setHostAccess(i, v)}
                        />
                      </div>
                    </>
                  );
                }}
```

Note the `noticeId` string changed shape (`…-host-0-passthrough-notice` instead of `…-passthrough-notice-0`); nothing asserts the literal — the existing tests read it off `aria-describedby`. Then the two `EditableList` props below the hosts `renderRow`:

```tsx
                rowAriaLabel={(r, i) => `Remove ${ruleName("host", r.host, i)}`}
                rowLabel={(r, i) => ruleName("host", r.host, i)}
```

3d. Git rows. Replace the git `renderRow` and its two naming props:

```tsx
                renderRow={(gr, i) => {
                  // #244: git rows have no visible field labels (and must not
                  // gain any — appearance is frozen), so the names are plain
                  // aria-label strings built from the same `ruleName`.
                  const rule = ruleName("git", gr.target, i);
                  return (
                    <div className="flex w-full items-center gap-2">
                      <Input
                        aria-label={`Repo for ${rule}`}
                        value={gr.target}
                        onChange={(e) => setGitTarget(i, e.target.value)}
                        placeholder="github.com/owner/repo"
                        className="flex-1 font-mono text-sm"
                      />
                      <AccessPicker
                        aria-label={`Access for ${rule}`}
                        value={gr.access}
                        onChange={(v) => setGitAccess(i, v)}
                      />
                    </div>
                  );
                }}
                onAdd={addGitRow}
                onRemove={(i) => removeGitRow(i)}
                addLabel="Add repo"
                emptyHint="No git rules — add one to allow a repo."
                rowAriaLabel={(gr, i) => `Remove ${ruleName("git", gr.target, i)}`}
                rowLabel={(gr, i) => ruleName("git", gr.target, i)}
```

- [ ] **Step 4: Update the existing tests that targeted the old names**

In `app/src/test/policyEditor.test.tsx`, every selector below must change (line numbers are from the pre-change file; find them by content):

| Old selector | New selector |
| --- | --- |
| `screen.getAllByLabelText("add port")` then `adders[1]` (≈ lines 69, 88) | `screen.getByRole("textbox", { name: "Add port to host rule 2 (db.internal)" })` |
| `screen.getAllByLabelText("add port")[0]` (≈ lines 107, 137, 146) | `screen.getByRole("textbox", { name: "Add port to host rule 1 (api.x.com)" })` |
| `screen.getByLabelText("add port")` (≈ line 325) | `screen.getByRole("textbox", { name: "Add port to host rule 1 (pinned.vendor.com)" })` |
| `screen.getAllByRole("button", { name: /^add$/i })[1]` (≈ line 90) | `screen.getByRole("button", { name: "Add port to host rule 2 (db.internal)" })` |
| `screen.getAllByRole("button", { name: /^add$/i })[0]` (≈ lines 130, 139, 148) | `screen.getByRole("button", { name: "Add port to host rule 1 (api.x.com)" })` |
| `screen.getByRole("button", { name: /^add$/i })` (≈ line 326) | `screen.getByRole("button", { name: "Add port to host rule 1 (pinned.vendor.com)" })` |
| `screen.getByRole("button", { name: /remove port 80/i })` (≈ line 155) | `screen.getByRole("button", { name: "Remove port 80 from host rule 1 (api.x.com)" })` |
| `screen.getByPlaceholderText("github.com/owner/repo")` (≈ lines 209, 220) | `screen.getByRole("textbox", { name: "Repo for git rule 1 (empty)" })` |

Then grep the file for any remaining `"add port"`, `/^add$/`, `PlaceholderText`, `Remove host`, `Remove repo` and convert the same way — the AC is that tests query by accessible name, not by placeholder or DOM position. Keep the comment on the `db.internal` row ("Second row … has the second add-port input") accurate by rewording it to "the second row's add-port field is named by its rule".

- [ ] **Step 5: Run the whole policy-editor suite, then the whole unit project**

Run (from `app/`): `npx vitest run --project=unit src/test/policyEditor.test.tsx`

Expected: PASS, every test (the `#239` lock/widening tests included).

Run (from `app/`): `npx vitest run --project=unit`

Expected: PASS. If `seedDialog`/`netlogView`/`newSandbox` tests fail, the AccessPicker default or EditableList default regressed — fix the default, do not edit those tests.

- [ ] **Step 6: Lint, typecheck, build, commit**

Run (from `app/`): `npm run lint && npm run build`

Expected: clean (`tsc` is part of `build`). Then:

```bash
git add app/src/components/PolicyEditor.tsx app/src/test/policyEditor.test.tsx
git diff --cached --stat
git commit -m "fix(app): name every policy-editor control by the rule it belongs to

Every host row's Host, Ports and Access control, every git row's
Repo and Access control, every row remove button and every port
chip's remove button now carry a distinct, row-identifying
accessible name built from one descriptor: 'host rule N (<host>)'
/ 'git rule N (<target>)'. The visible Host/Ports/Access labels are
programmatically associated with their controls (htmlFor +
aria-labelledby, so the name is the visible text followed by the
rule), each rule is a labelled group, and a blank or duplicated
value can never collide thanks to the ordinal.

Before, every host input was named by its shared placeholder, every
add-port field was 'add port', every Access control was 'access',
the git input had no name at all, and remove buttons were named by
position — a screen-reader user could not tell which egress rule
they were editing, and the dogfood driver's set-of-marks could not
target rows except by guessing.

Appearance is unchanged: the only new DOM is a visually-hidden
'for <rule>' span per host row and id/aria attributes.

Refs #244"
```

(Final trailer line: `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.)

---

### Task 3: Full app gate + browser project

**Files:** none modified (verification only), unless a gate fails.

- [ ] **Step 1: Run the full front-end gate**

Run (from `app/`): `npm run lint && npm run build && npm run test`

`npm run test` runs both the `unit` and `browser` Vitest projects with coverage. The browser project needs Chromium; if it fails with a missing-browser error, run `npm run e2e:install:chromium:deps` once and retry. If Chromium genuinely cannot run in this environment, run `npx vitest run --project=unit --coverage` and record in the final report that the browser project was left to CI (the App CI workflow runs it).

Expected: PASS.

- [ ] **Step 2: Confirm nothing outside the intended files changed**

Run: `git diff --stat origin/main..HEAD`

Expected: exactly `app/src/components/PolicyEditor.tsx`, `app/src/components/AccessPicker.tsx`, `app/src/components/ui/segmented-control.tsx`, `app/src/components/ui/editable-list.tsx`, `app/src/components/ui/row-editor.tsx`, `app/src/test/policyEditor.test.tsx`, `app/src/test/accessPicker.test.tsx`, `app/src/test/ui/segmentedControl.test.tsx`, `app/src/test/ui/editableList.test.tsx`, and this plan under `docs/superpowers/plans/`. No `src-tauri`, `e2e`, or `hack/` changes.
