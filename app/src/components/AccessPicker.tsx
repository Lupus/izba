import type { Access } from "../lib/types";
import { SegmentedControl, type SegmentedControlName } from "@/components/ui/segmented-control";

/** The read / read-write segmented control. Its accessible name defaults to
 *  "access" (SeedDialog renders one per candidate inside a row that is itself
 *  the label). A caller whose rows need to be told apart — PolicyEditor, #244
 *  — names it by the rule it belongs to, either with an `aria-label` string or
 *  with `aria-labelledby` ids; when `aria-labelledby` is given no `aria-label`
 *  is rendered, so the two never compete for the name. */
export function AccessPicker({
  id,
  value,
  onChange,
  ...aria
}: {
  /** Forwarded to SegmentedControl: stable per-item ids for a `<label htmlFor>`. */
  id?: string;
  value: Access;
  onChange: (v: Access) => void;
  "aria-label"?: string;
  "aria-labelledby"?: string;
}) {
  const labelledby = aria["aria-labelledby"];
  const name: SegmentedControlName = labelledby
    ? { "aria-labelledby": labelledby }
    : { "aria-label": aria["aria-label"] ?? "access" };
  return (
    <SegmentedControl<Access>
      {...name}
      id={id}
      value={value}
      onChange={onChange}
      options={[
        { value: "read", label: "read" },
        { value: "read-write", label: "read-write" },
      ]}
    />
  );
}
