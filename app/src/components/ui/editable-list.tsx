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
