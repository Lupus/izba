import * as React from "react";
import { RowList, RowCard, AddRowButton, RemoveRowButton } from "@/components/ui/row-editor";

export interface EditableListProps<T> {
  items: T[];
  renderRow: (item: T, index: number) => React.ReactNode;
  onAdd: () => void;
  onRemove: (index: number) => void;
  addLabel: string;
  emptyHint: string;
  density?: "inline" | "card";
  rowAriaLabel?: (item: T, index: number) => string;
  /** When given, each row is a labelled `role="group"` named by this — so a
   *  screen reader (and the dogfood driver's set-of-marks) can tell rows
   *  apart as units, not only by their individual controls (#244). Absent ⇒
   *  no group role, markup identical to before. */
  rowLabel?: (item: T, index: number) => string;
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
  rowLabel,
  addDisabled,
}: EditableListProps<T>) {
  const label = (item: T, i: number) => rowAriaLabel?.(item, i) ?? `Remove ${i + 1}`;
  const groupProps = (item: T, i: number) =>
    rowLabel ? { role: "group" as const, "aria-label": rowLabel(item, i) } : {};

  return (
    <div className="flex flex-col gap-2">
      {items.length === 0 ? (
        <p className="text-sm text-muted-foreground-2">{emptyHint}</p>
      ) : (
        <RowList>
          {items.map((item, i) =>
            density === "card" ? (
              // Fields fill a flex-1 column; the remove button sits in its own
              // column pinned to the card's top-right corner (items-start).
              <RowCard key={i} className="items-start p-3" {...groupProps(item, i)}>
                <div className="flex min-w-0 flex-1 flex-col gap-2">{renderRow(item, i)}</div>
                <RemoveRowButton aria-label={label(item, i)} onClick={() => onRemove(i)} />
              </RowCard>
            ) : (
              // key=index is safe here: rows are fully controlled by the parent's
              // items state (no uncontrolled per-row state lives in the wrapper).
              <div key={i} className="flex flex-wrap items-center gap-2" {...groupProps(item, i)}>
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
