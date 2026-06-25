import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { SegmentedControl } from "@/components/ui/segmented-control";

describe("SegmentedControl", () => {
  const opts = [{ value: "read", label: "read" }, { value: "read-write", label: "read-write" }];
  it("renders all options and marks the active one pressed", () => {
    render(<SegmentedControl aria-label="access" value="read" onChange={() => {}} options={opts} />);
    expect(screen.getByRole("radio", { name: "read" })).toHaveAttribute("data-state", "on");
  });
  it("fires onChange with the chosen value", () => {
    const onChange = vi.fn();
    render(<SegmentedControl aria-label="access" value="read" onChange={onChange} options={opts} />);
    fireEvent.click(screen.getByRole("radio", { name: "read-write" }));
    expect(onChange).toHaveBeenCalledWith("read-write");
  });
});
