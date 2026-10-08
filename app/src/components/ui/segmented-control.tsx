import * as ToggleGroup from "@radix-ui/react-toggle-group";
import { cn } from "@/lib/utils";

export interface SegmentedOption<T extends string> {
  value: T;
  label: string;
}

/** The group's accessible name — exactly one path, enforced by the type: a
 *  literal `aria-label`, or `aria-labelledby` (space-separated element ids;
 *  the name is the referenced elements' text, concatenated in order). A
 *  caller that passes neither no longer compiles, so a shared control can
 *  never render an unnamed radiogroup. */
export type SegmentedControlName =
  | { "aria-label": string; "aria-labelledby"?: never }
  | { "aria-labelledby": string; "aria-label"?: never };

/** The ONE place the item-id shape is defined. */
export function segmentedItemId(id: string, value: string): string {
  return `${id}-${value}`;
}

export type SegmentedControlProps<T extends string> = {
  /** When given, each item gets a stable id `segmentedItemId(id, value)`, so a
   *  visible `<label htmlFor>` can target the checked item and focus it.
   *  Absent ⇒ no ids rendered (markup unchanged). */
  id?: string;
  value: T;
  onChange: (value: T) => void;
  options: SegmentedOption<T>[];
  className?: string;
} & SegmentedControlName;

export function SegmentedControl<T extends string>({
  id,
  value,
  onChange,
  options,
  className,
  ...aria
}: SegmentedControlProps<T>) {
  return (
    <ToggleGroup.Root
      type="single"
      value={value}
      onValueChange={(v) => v && onChange(v as T)}
      aria-label={aria["aria-label"]}
      aria-labelledby={aria["aria-labelledby"]}
      className={cn("inline-flex gap-1 rounded-lg border border-input p-0.5", className)}
    >
      {options.map((o) => (
        <ToggleGroup.Item
          key={o.value}
          value={o.value}
          id={id ? segmentedItemId(id, o.value) : undefined}
          // An explicit aria-label equal to the visible text shields the
          // item's accessible name from a native <label> aimed at it (which
          // would otherwise rename the radio to the label's text); it is
          // identical to the content, so nothing changes for callers
          // without a label.
          aria-label={o.label}
          className={cn(
            "rounded px-2 py-1 text-xs font-semibold transition-colors",
            "text-muted-foreground hover:bg-muted",
            "data-[state=on]:bg-primary data-[state=on]:text-primary-foreground",
          )}
        >
          {o.label}
        </ToggleGroup.Item>
      ))}
    </ToggleGroup.Root>
  );
}
