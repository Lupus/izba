import type { Access } from "../lib/types";
import { SegmentedControl } from "@/components/ui/segmented-control";

export function AccessPicker({ value, onChange }: { value: Access; onChange: (v: Access) => void }) {
  return (
    <SegmentedControl<Access>
      aria-label="access"
      value={value}
      onChange={onChange}
      options={[
        { value: "read", label: "read" },
        { value: "read-write", label: "read-write" },
      ]}
    />
  );
}
