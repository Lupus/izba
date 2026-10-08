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
