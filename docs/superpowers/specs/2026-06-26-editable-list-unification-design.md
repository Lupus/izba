# EditableList — unify the add/edit-row pattern across the izba app

> **Status:** design approved 2026-06-26 (follow-up to the shadcn component
> system, PR #103). Scope: the Tauri GUI `app/` only.

## Problem

The shadcn migration (PR #103) unified primitive *styling* but not the
*composition* of editable collections. Post-migration UX review surfaced that
the four "list of editable rows" surfaces diverge:

1. **Two interaction models.** PortsTab uses an always-visible inline *template
   row* with the add button to the right of empty inputs (fill → click to
   commit). VolumesTab / PolicyEditor / NewSandbox use *click-to-append* (a
   button below the list spawns a fresh blank editable row; no form until you
   click).
2. **Add-button height.** `AddRowButton` is `size="sm"` (`py-1`) but `Input` is
   `py-1.5` → in Ports the add button is visibly shorter than the inputs beside
   it.
3. **Add-button surface.** `AddRowButton` is the `secondary` variant
   (transparent background), so it shows the surface behind it — white inside
   PolicyEditor's `RowCard`, gray over VolumesTab's plain section.
4. **Label drift.** `"+ Add volume"`, `"+ Add port"` vs `"Add forward"`,
   `"Add host"`, `"Add repo"` (literal `"+"` inconsistent).
5. **Row container drift.** Policy rows are bordered cards; ports/volumes rows
   are not — the visible cause of the white-vs-gray button difference.

The migration's ESLint gate cannot see any of this (it's composition/layout, not
raw controls or arbitrary values), so it must be fixed by design + a shared
composite.

## Decisions (locked during brainstorming)

1. **One interaction model:** click-to-append a blank editable row; the add
   button lives **below the list, left-aligned**. Ports loses its inline
   template row.
2. **Empty state:** when a collection is empty, show a **muted one-line hint**
   above the add button (e.g. *"No forwards — add one to publish a port"*).
   **No always-present blank row.**
3. **One composite — `EditableList`** — owns the chrome for every collection:
   the row list, the per-row remove control, the empty-state hint, and the add
   button. Consistent by construction; one place to evolve.
4. **Row density is driven by content type, applied consistently across tabs**
   (not chosen per-tab):
   - **`inline` (borderless):** compact single-line rows. → Ports forwards,
     New-sandbox ports.
   - **`card` (bordered `RowCard`):** multi-control *form* rows. → Volumes +
     New-sandbox volumes (type-segmented + path + name), Policy host rows
     (host + access picker), Policy git/repo rows (kept carded so PolicyEditor's
     two lists stay uniform).
   - Rule: *compact one-line → borderless; multi-control form → carded.*
5. **One add affordance everywhere**, independent of density:
   - **Solid, surface-independent background** (no transparent `secondary`) —
     identical over any surface.
   - **Height matches inputs** (`py-1.5`; i.e. the button's default size, not
     the shrunk `sm`).
   - Leading **lucide `Plus` icon + `"Add <thing>"`** label (no literal `"+"`).
   - **Below the list, left-aligned.**

## Architecture

### `app/src/components/ui/editable-list.tsx` (new composite)

Generic over the row item type. It owns list/empty/add/remove chrome; the caller
supplies only the row's fields via a render prop.

```tsx
export interface EditableListProps<T> {
  items: T[];
  renderRow: (item: T, index: number) => React.ReactNode; // fields ONLY
  onAdd: () => void;            // caller appends a blank item
  onRemove: (index: number) => void;
  addLabel: string;            // e.g. "Add forward"
  emptyHint: string;           // shown (muted) when items.length === 0
  density?: "inline" | "card"; // default "inline"
  rowAriaLabel?: (item: T, index: number) => string; // remove button a11y
  addDisabled?: boolean;
}
```

Behavior:
- `items.length === 0` → render `emptyHint` (muted text) then the add button.
- Otherwise → render each row, each wrapped by EditableList:
  - `density="inline"`: a borderless flex row — `renderRow(...)` fields + a
    trailing `RemoveRowButton`.
  - `density="card"`: a `RowCard` containing `renderRow(...)` + the
    `RemoveRowButton` (top-right for multi-line forms).
  - then the add button below the list.
- The add button is rendered via the revised `AddRowButton` (see below).

The composite reuses existing primitives: `RowList`, `RowCard`,
`RemoveRowButton`, `AddRowButton`. **Row components render fields only** — they
must NOT render their own remove button or list container anymore (EditableList
owns them).

### `app/src/components/ui/row-editor.tsx` (revise `AddRowButton`)

- Drop the transparent `secondary` variant; give the add button a **solid,
  surface-independent** treatment (a dedicated style — e.g. `Button` with a
  solid `bg-card` + `border-input` + `hover:bg-muted`, or a new `variant` — TBD
  in the plan, but it MUST look identical on any surface and use only tokens).
- Size = default (`py-1.5`) so it matches `Input` height.
- Render a leading lucide `Plus` icon before the label text.
- Keep it left-aligned (`self-start`).

### Per-collection migration

Each tab replaces its hand-rolled list + add/remove wiring with `EditableList`,
passing the row fields via `renderRow` and the right `density`:

- **PortsTab** (`density="inline"`): the committed-forwards list + the inline
  "Add forward" template both collapse into one `EditableList`; clicking Add
  appends a blank forward row (bind/host/guest inputs inline). Remove via
  EditableList.
- **VolumesTab** (`density="card"`): `VolumeRowEditor` becomes fields-only
  (no own remove); EditableList wraps it.
- **PolicyEditor** (`density="card"`, both the hosts list and the git/repos
  list): host-row and git-row become fields-only; two `EditableList`s.
- **NewSandbox** (ports `inline`, volumes `card`): same row components as the
  tabs above.

## Testing

- **`EditableList` unit tests (TDD):** empty → shows hint + add button; click
  Add → `onAdd` fired; with items → renders N rows each with a remove button;
  click remove → `onRemove(index)`; `density` switches borderless vs carded
  (assert container class); add button has the `Plus` icon + label.
- **Regression — existing per-tab tests stay green.** They assert add/remove
  *behavior* (clicking Add adds a row; Remove removes; submit produces the right
  spec). Migrating to EditableList changes DOM structure → update only
  style/query assertions (e.g. the add button is now found by its accessible
  name "Add forward"); **never weaken a behavior assertion.** The Radix `Select`
  inside the volume row is unchanged, so the existing `*.browser.test.tsx`
  (open+pick) tests are unaffected.
- Gates unchanged: `npm run lint` (0), `npm run build`, `npm run test`
  (unit + browser), SonarCloud, Greptile.

## Non-goals

- Not changing which fields each row contains, nor validation logic.
- Not the deferred visual-regression/pixel-diff gate.
- No new interaction affordances (drag-reorder, inline-edit-toggle, etc.).

## Risks

1. **Remove-ownership refactor.** Moving the remove button out of
   `VolumeRowEditor` / policy rows into `EditableList` is the most invasive part;
   the row components must become pure field groups. Behavior tests guard this.
2. **PortsTab model change.** Dropping the inline template alters Ports' UX
   (fill-inline → click-to-add-then-fill). Its tests assert the
   commit-forward behavior; verify the new flow preserves it.
3. **Empty-row submission semantics.** With click-to-append, a user may add a
   blank row and not fill it; preserve each tab's existing "ignore
   empty/incomplete rows on submit" behavior (NewSandbox already does this).
