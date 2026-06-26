# EditableList add-row unification — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Unify the add/edit-row pattern across the izba app: one `EditableList` composite (click-to-append) for the declarative collections, one surface-independent add button at input height with a `Plus` icon, and a tidied PortsTab create-form — fixing the interaction-model, height, surface, label, and row-container drift surfaced in PR #103 UX review.

**Architecture:** A new `EditableList<T>` composite owns list/empty-hint/add/remove chrome; row components become **fields-only** (no own remove/container). Row density (`inline` borderless vs `card`) is chosen by content type, consistent across tabs. The `AddRowButton` primitive is revised to a solid, surface-independent, input-height button with a leading `Plus` icon. PortsTab keeps its live-list + create-form model but adopts the unified add button.

**Tech Stack:** React 18, TypeScript, Tailwind 3 (shadcn-native tokens), Vitest 4 (jsdom `unit` + chromium `browser` projects), @testing-library/react, lucide-react.

## Global Constraints

- **Scope is `app/` only.** No backend/Rust/CLI changes.
- **No arbitrary Tailwind values** (`tailwindcss/no-arbitrary-value` gate) and **no raw `<button>/<input>/<select>/<textarea>`** in feature components (`izba/no-raw-control`; `src/components/ui/**` + `*.test.tsx` exempt). **No `eslint-disable`** for these (pre-existing `react-hooks/exhaustive-deps` disables stay).
- **Behavior assertions are sacrosanct.** Migrating to EditableList changes DOM structure — update ONLY style/query assertions in existing tests; never weaken a text/role/click/state/submit-spec assertion. If one must change, STOP and report.
- **One interaction model (declarative surfaces):** click-to-append a blank editable row; add button below the list, left-aligned; empty state = muted one-line hint above the add button; NO always-present blank row.
- **Row density by content:** `inline` (borderless) = NewSandbox ports; `card` (RowCard) = Volumes, NewSandbox volumes, Policy hosts, Policy git/repos.
- **PortsTab is NOT EditableList** — it keeps its live/persisted-forwards table + immediate-apply create-form; it only adopts the unified add button + a tidied create-form layout (add button below the inputs, not inline-right).
- **Unified add button:** solid surface-independent background (token-only; identical over any surface), height = `Input` height (`py-1.5`, i.e. button default size not `sm`), leading lucide `Plus` icon, `"Add <thing>"` label (no literal `"+"`), left-aligned.
- **Row components render fields ONLY** — EditableList owns the remove button and the row container (RowCard for `card`, plain row for `inline`).
- **TDD**; commit per task; stage only touched files (no `git add -A`).
- **Gates:** `npm run lint` (0), `npm run build`, `npm run test` (unit+browser) all green per task where applicable.

---

## Task 1: Revise `AddRowButton` — solid, input-height, `Plus` icon

**Files:**
- Modify: `app/src/components/ui/row-editor.tsx`
- Test: `app/src/test/ui/rowEditor.test.tsx`

**Interfaces:**
- Produces: `AddRowButton({ onClick, children, disabled })` — now renders a leading `Plus` icon before `children`, uses a solid surface-independent style, and is `Input`-height (button default size). Unchanged prop shape.

- [ ] **Step 1: Update the failing test** — extend `app/src/test/ui/rowEditor.test.tsx`'s AddRowButton case to assert the new look (add these assertions to the existing "AddRowButton fires onClick" test or a new test):

```tsx
import { Plus } from "lucide-react";
// ...
it("AddRowButton renders a leading Plus icon and a solid (non-transparent) surface", () => {
  const { container } = render(<AddRowButton onClick={() => {}}>Add volume</AddRowButton>);
  const btn = screen.getByRole("button", { name: "Add volume" });
  // solid, surface-independent background (not bg-transparent)
  expect(btn.className).toContain("bg-card");
  expect(btn.className).not.toContain("bg-transparent");
  // leading icon present (lucide renders an <svg>)
  expect(container.querySelector("svg")).toBeInTheDocument();
});
```

- [ ] **Step 2: Run it, verify it fails**

Run: `cd app && npx vitest run --project unit src/test/ui/rowEditor.test.tsx`
Expected: FAIL — current AddRowButton uses `variant="secondary"` (`bg-transparent`) and no icon.

- [ ] **Step 3: Revise `AddRowButton` in `app/src/components/ui/row-editor.tsx`**

```tsx
import * as React from "react";
import { Plus, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

// ... RowList, RowCard unchanged ...

export function AddRowButton({
  onClick,
  children,
  disabled,
}: {
  onClick: () => void;
  children: React.ReactNode;
  disabled?: boolean;
}) {
  return (
    <Button
      type="button"
      variant="outline"
      onClick={onClick}
      disabled={disabled}
      // Solid, surface-independent background so it looks identical over a
      // card (white) or a plain section (gray) — fixes the transparent-secondary
      // white-vs-gray drift. Default size = Input height (py-1.5).
      className="self-start gap-1.5 bg-card hover:bg-muted"
    >
      <Plus className="h-4 w-4" />
      {children}
    </Button>
  );
}

// RemoveRowButton unchanged.
```

- [ ] **Step 4: Run it, verify it passes**

Run: `cd app && npx vitest run --project unit src/test/ui/rowEditor.test.tsx`
Expected: PASS.

- [ ] **Step 5: Confirm existing direct callers still pass + lint/build green**

Run: `cd app && npx vitest run --project unit src/test/portsTab.test.tsx src/test/volumesTab.test.tsx src/test/newSandbox.test.tsx src/test/policyEditor.test.tsx && npx eslint src/components/ui/row-editor.tsx && npm run build`
Expected: all PASS / 0 problems / build green. (Existing add-button queries use regex/substring names like `/Add forward/`, so the leading icon + unchanged text still match. The literal `"+"` in some labels is removed in the migration tasks below.)

- [ ] **Step 6: Commit**

```bash
git add app/src/components/ui/row-editor.tsx app/src/test/ui/rowEditor.test.tsx
git commit -m "feat(app): AddRowButton — solid surface-independent, input-height, Plus icon"
```

---

## Task 2: Build the `EditableList` composite

**Files:**
- Create: `app/src/components/ui/editable-list.tsx`
- Test: `app/src/test/ui/editableList.test.tsx`

**Interfaces:**
- Produces:
```tsx
export interface EditableListProps<T> {
  items: T[];
  renderRow: (item: T, index: number) => React.ReactNode; // fields ONLY
  onAdd: () => void;
  onRemove: (index: number) => void;
  addLabel: string;            // e.g. "Add forward" (no "+")
  emptyHint: string;           // muted text when items.length === 0
  density?: "inline" | "card"; // default "inline"
  rowAriaLabel?: (item: T, index: number) => string; // remove a11y, default `Remove ${index+1}`
  addDisabled?: boolean;
}
export function EditableList<T>(props: EditableListProps<T>): JSX.Element;
```

- [ ] **Step 1: Write the failing test** — `app/src/test/ui/editableList.test.tsx`

```tsx
import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { EditableList } from "@/components/ui/editable-list";

describe("EditableList", () => {
  it("shows the empty hint + add button when there are no items", () => {
    render(
      <EditableList
        items={[]}
        renderRow={() => null}
        onAdd={() => {}}
        onRemove={() => {}}
        addLabel="Add forward"
        emptyHint="No forwards — add one to publish a port"
      />,
    );
    expect(screen.getByText(/No forwards/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Add forward" })).toBeInTheDocument();
  });

  it("fires onAdd when the add button is clicked", () => {
    const onAdd = vi.fn();
    render(
      <EditableList items={[]} renderRow={() => null} onAdd={onAdd} onRemove={() => {}}
        addLabel="Add host" emptyHint="none" />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Add host" }));
    expect(onAdd).toHaveBeenCalledOnce();
  });

  it("renders a row per item with the fields and a remove button; fires onRemove(index)", () => {
    const onRemove = vi.fn();
    render(
      <EditableList
        items={["a", "b"]}
        renderRow={(item) => <span>row-{item}</span>}
        onAdd={() => {}}
        onRemove={onRemove}
        addLabel="Add"
        emptyHint="none"
        rowAriaLabel={(_, i) => `Remove row ${i + 1}`}
      />,
    );
    expect(screen.getByText("row-a")).toBeInTheDocument();
    expect(screen.getByText("row-b")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Remove row 2" }));
    expect(onRemove).toHaveBeenCalledWith(1);
  });

  it("card density wraps each row in a bordered RowCard; inline does not", () => {
    const { rerender } = render(
      <EditableList items={["a"]} renderRow={() => <span>x</span>} onAdd={() => {}}
        onRemove={() => {}} addLabel="Add" emptyHint="none" density="card" />,
    );
    expect(screen.getByText("x").closest(".rounded-lg.border")).not.toBeNull();
    rerender(
      <EditableList items={["a"]} renderRow={() => <span>y</span>} onAdd={() => {}}
        onRemove={() => {}} addLabel="Add" emptyHint="none" density="inline" />,
    );
    expect(screen.getByText("y").closest(".rounded-lg.border")).toBeNull();
  });
});
```

- [ ] **Step 2: Run it, verify it fails**

Run: `cd app && npx vitest run --project unit src/test/ui/editableList.test.tsx`
Expected: FAIL — module missing.

- [ ] **Step 3: Create `app/src/components/ui/editable-list.tsx`**

```tsx
import * as React from "react";
import { RowList, RowCard, AddRowButton, RemoveRowButton } from "@/components/ui/row-editor";
import { cn } from "@/lib/utils";

export interface EditableListProps<T> {
  items: T[];
  renderRow: (item: T, index: number) => React.ReactNode;
  onAdd: () => void;
  onRemove: (index: number) => void;
  addLabel: string;
  emptyHint: string;
  density?: "inline" | "card";
  rowAriaLabel?: (item: T, index: number) => string;
  addDisabled?: boolean;
}

export function EditableList<T>({
  items,
  renderRow,
  onAdd,
  onRemove,
  addLabel,
  emptyHint,
  density = "inline",
  rowAriaLabel,
  addDisabled,
}: EditableListProps<T>) {
  const label = (item: T, i: number) => rowAriaLabel?.(item, i) ?? `Remove ${i + 1}`;

  return (
    <div className="flex flex-col gap-2">
      {items.length === 0 ? (
        <p className="text-sm text-muted-foreground-2">{emptyHint}</p>
      ) : (
        <RowList>
          {items.map((item, i) =>
            density === "card" ? (
              <RowCard key={i} className="flex-col items-stretch p-3">
                <div className="flex flex-col gap-2">{renderRow(item, i)}</div>
                <div className="flex justify-end">
                  <RemoveRowButton aria-label={label(item, i)} onClick={() => onRemove(i)} />
                </div>
              </RowCard>
            ) : (
              <div key={i} className={cn("flex flex-wrap items-center gap-2")}>
                {renderRow(item, i)}
                <RemoveRowButton aria-label={label(item, i)} onClick={() => onRemove(i)} />
              </div>
            ),
          )}
        </RowList>
      )}
      <AddRowButton onClick={onAdd} disabled={addDisabled}>
        {addLabel}
      </AddRowButton>
    </div>
  );
}
```

- [ ] **Step 4: Run it, verify it passes**

Run: `cd app && npx vitest run --project unit src/test/ui/editableList.test.tsx`
Expected: PASS (4 tests).

- [ ] **Step 5: Lint + build**

Run: `cd app && npx eslint src/components/ui/editable-list.tsx && npm run build`
Expected: 0 problems / build green.

- [ ] **Step 6: Commit**

```bash
git add app/src/components/ui/editable-list.tsx app/src/test/ui/editableList.test.tsx
git commit -m "feat(app): EditableList composite (click-to-append, empty hint, density)"
```

---

## Task 3: Migrate PolicyEditor (hosts + git) to `EditableList`

**Files:**
- Modify: `app/src/components/PolicyEditor.tsx`
- Keep green: `app/src/test/policyEditor.test.tsx`

**Interfaces:**
- Consumes: `EditableList` (Task 2). Density `card`.

- [ ] **Step 1:** Replace the hand-rolled hosts `RowList`/`RowCard`/`AddRowButton`/`RemoveRowButton` block with `<EditableList density="card" items={hosts} renderRow={(h,i)=> <host fields> } onAdd={addRow} onRemove={(i)=>removeRow(i)} addLabel="Add host" emptyHint="No allowed hosts — add one to permit egress." rowAriaLabel={(_,i)=>\`Remove host ${i+1}\`} />`. The host **row fields** (the host `Input` + `AccessPicker`/SegmentedControl) move into `renderRow`; the per-row `RemoveRowButton` and the outer `RowCard` are now owned by EditableList — delete them from the inline JSX. Do the same for the git/repos list (`addLabel="Add repo"`, `emptyHint="No git rules — add one to allow a repo."`, density `card`).

- [ ] **Step 2:** Preserve behavior: the `addRow`/`addGitRow`/remove handlers and the policy-save call args are unchanged. `policyEditor.test.tsx` has class/role assertions — update only the queries that targeted the old add/remove markup (the add button is found by name "Add host"/"Add repo"; remove by "Remove host N"); keep all policy-save behavior assertions. Run: `cd app && npx vitest run --project unit src/test/policyEditor.test.tsx` → PASS.

- [ ] **Step 3:** `cd app && npx eslint src/components/PolicyEditor.tsx` → 0 problems; `npm run build` → green.

- [ ] **Step 4:** Commit `refactor(app): migrate PolicyEditor lists to EditableList`.

---

## Task 4: Migrate VolumesTab to `EditableList`; make `VolumeRowEditor` fields-only

**Files:**
- Modify: `app/src/components/VolumeRowEditor.tsx` (drop `onRemove` + outer card + RemoveRowButton — fields only)
- Modify: `app/src/components/VolumesTab.tsx`
- Keep green: `app/src/test/volumesTab.test.tsx`, `app/src/test/detail.test.tsx`, `app/src/test/browser/volumeRowEditor.browser.test.tsx`, `app/src/test/browser/volumeIpcSpec.browser.test.tsx`

**Interfaces:**
- Produces: `VolumeRowEditor` Props drop `onRemove`; it renders ONLY the field group (no outer `rounded-lg border p-3`, no `RemoveRowButton`). Signature becomes `{ row, freeVolumes, onChange, index }`.
- Consumes: `EditableList` density `card`.

- [ ] **Step 1:** Edit `VolumeRowEditor.tsx`: remove the `onRemove` prop, the trailing `<div className="flex justify-end"><RemoveRowButton .../></div>`, and the outer `<div className="flex flex-col gap-2 rounded-lg border border-border p-3">` wrapper — return a `<>…</>` fragment (or a plain `<div className="flex flex-col gap-2">`) of just the segmented control + conditional fields. Remove the now-unused `RemoveRowButton` import.

- [ ] **Step 2:** In `VolumesTab.tsx`, replace the new-volume-rows mapping + the standalone `AddRowButton` with:
```tsx
<EditableList
  density="card"
  items={volumeRows}
  renderRow={(row, i) => (
    <VolumeRowEditor
      row={row}
      index={i}
      freeVolumes={freeVolumes(allVolumes, seededNames, usedExistingNames(volumeRows, i))}
      onChange={(r) => setVolumeRow(i, r)}
    />
  )}
  onAdd={addVolume}
  onRemove={removeVolume}
  addLabel="Add volume"
  emptyHint="No volumes — add one to mount it."
  rowAriaLabel={(_, i) => `Remove volume ${i + 1}`}
/>
```
(The seeded/existing-attached volumes section above is unchanged.) Keep the `removeVolume(i)` handler.

- [ ] **Step 3:** Update `volumeRowEditor.browser.test.tsx` + `volumeIpcSpec.browser.test.tsx`: they render `VolumeRowEditor` (or VolumesTab/NewSandbox). For the direct `VolumeRowEditor` render, drop the `onRemove` prop. The remove-behavior assertions (if any in the browser test) move to where EditableList owns remove — but the browser tests assert Select open+pick and IPC spec, not remove, so they should only need the `onRemove` prop dropped. Keep the open+pick + IPC assertions intact.

- [ ] **Step 4:** Run: `cd app && npx vitest run --project unit src/test/volumesTab.test.tsx src/test/detail.test.tsx && npx vitest run --project browser src/test/browser/volumeRowEditor.browser.test.tsx src/test/browser/volumeIpcSpec.browser.test.tsx` → all PASS. Update only style/query assertions (remove now found via EditableList's "Remove volume N"); preserve add/remove/save behavior + the IPC composite-spec assertions.

- [ ] **Step 5:** `cd app && npx eslint src/components/VolumeRowEditor.tsx src/components/VolumesTab.tsx` → 0 problems; `npm run build` → green.

- [ ] **Step 6:** Commit `refactor(app): VolumeRowEditor fields-only; VolumesTab via EditableList`.

---

## Task 5: Migrate NewSandbox (ports inline + volumes card) to `EditableList`

**Files:**
- Modify: `app/src/components/NewSandbox.tsx`
- Keep green: `app/src/test/newSandbox.test.tsx`, `app/src/test/browser/volumeIpcSpec.browser.test.tsx`

**Interfaces:**
- Consumes: `EditableList` (ports density `inline`, volumes density `card`), the fields-only `VolumeRowEditor` (Task 4).

- [ ] **Step 1:** Replace the NewSandbox **ports** rows + `AddRowButton` with `<EditableList density="inline" items={ports} renderRow={(p,i)=> <bind/host/guest Inputs for row i> } onAdd={addPort} onRemove={removePort} addLabel="Add port" emptyHint="No published ports — add one to forward a port." rowAriaLabel={(_,i)=>\`Remove port ${i+1}\`} />`. The port-row `Input`s move into `renderRow`; the inline `RemoveRowButton` per port row is now owned by EditableList — delete it. (Keep the port grid alignment classes inside `renderRow` as needed, token-only.)

- [ ] **Step 2:** Replace the NewSandbox **volumes** rows + `AddRowButton` with an `EditableList density="card"` mirroring Task 4's VolumesTab usage (using `freeVolumesFor(i)` and `setVolumeRow`/`addVolume`/`removeVolume`; `addLabel="Add volume"`, `emptyHint="No volumes — add one to mount it."`). The `VolumeRowEditor` is rendered fields-only via `renderRow`, no `onRemove`.

- [ ] **Step 3:** Run: `cd app && npx vitest run --project unit src/test/newSandbox.test.tsx && npx vitest run --project browser src/test/browser/volumeIpcSpec.browser.test.tsx` → PASS. Preserve the `create()` composite-spec assertions, the add/remove-row behavior, and the volume Select assertions; update only style/query assertions (add buttons by name "Add port"/"Add volume"; removes by "Remove port N"/"Remove volume N").

- [ ] **Step 4:** `cd app && npx eslint src/components/NewSandbox.tsx` → 0 problems; `npm run build` → green.

- [ ] **Step 5:** Commit `refactor(app): migrate NewSandbox ports+volumes to EditableList`.

---

## Task 6: PortsTab — adopt the unified add button + tidy the create-form

**Files:**
- Modify: `app/src/components/PortsTab.tsx`
- Keep green: `app/src/test/portsTab.test.tsx`

**Interfaces:**
- Consumes: the revised `AddRowButton` (Task 1). PortsTab does NOT use EditableList.

- [ ] **Step 1:** In the "Add forward" create-form (the `<div className="mt-2 grid gap-2">` block), move the `AddRowButton` **out of** the inline `<div className="flex flex-wrap items-center gap-2">` (which holds the bind/host/guest `Input`s) to its **own line below** that input row, left-aligned. The button already uses `AddRowButton` (now solid/input-height/Plus icon from Task 1) — no size override needed. The live/persisted-forwards table above is unchanged. Result: inputs on one row, the "Add forward" button on the next row, heights consistent, button surface-independent.

- [ ] **Step 2:** Run: `cd app && npx vitest run --project unit src/test/portsTab.test.tsx` → PASS. The add-forward behavior (fill inputs → click "Add forward" → `addForward()` applies) is unchanged; the button is still found by name `/Add forward/`. Update only any layout-class assertion if present (the test uses behavior/role queries — likely no change).

- [ ] **Step 3:** `cd app && npx eslint src/components/PortsTab.tsx` → 0 problems; `npm run build` → green.

- [ ] **Step 4:** Commit `refactor(app): tidy PortsTab add-forward form (unified add button below inputs)`.

---

## Task 7: Full gate + visual review

**Files:** none (verification + any fixups).

- [ ] **Step 1: Lint clean.** Run: `cd app && npm run lint` → exit 0.
- [ ] **Step 2: Build.** Run: `cd app && npm run build` → green.
- [ ] **Step 3: Full test suite (unit + browser).** Run: `cd app && npm run test` → all pass; confirm `EditableList` is covered and the browser Select/IPC tests still pass.
- [ ] **Step 4: Visual review.** Run the app (`npm run dev`) and confirm across Ports / Volumes / Policy / New-sandbox: every add button looks identical (solid, Plus icon, input height, below-left), the empty hints read well, removes are uniformly destructive, ports rows are borderless and volume/policy rows are carded, and the white-vs-gray button difference is gone.
- [ ] **Step 5: Final commit** (if any fixups): `chore(app): EditableList unification fixups`.

---

## Self-review notes

- **Spec coverage:** unified add button — Task 1 ✓; EditableList composite — Task 2 ✓; click-to-append + empty-hint model — Task 2 + migrations ✓; density inline/card by content — Task 2 (prop) + Tasks 3–5 ✓; PolicyEditor/Volumes/NewSandbox declarative migration — Tasks 3–5 ✓; VolumeRowEditor fields-only (remove-ownership refactor) — Task 4 ✓; PortsTab keeps live model + unified button — Task 6 ✓; label "+" removal — Tasks 3–5 (clean `addLabel`s) ✓; gates — Task 7 ✓.
- **Behavior-assertion safety** is restated per migration task, with explicit "preserve submit/IPC-spec + add/remove behavior, update only queries."
- **Type consistency:** `EditableListProps<T>` (Task 2) is consumed verbatim in Tasks 3–5; `VolumeRowEditor` losing `onRemove` (Task 4) is reflected in NewSandbox (Task 5) and the browser tests.
- **Risk (remove-ownership):** Task 4 is the most invasive (VolumeRowEditor → fields-only); its behavior is guarded by the unit + browser suites.
