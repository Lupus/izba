import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { SegmentedControl, segmentedItemId } from "@/components/ui/segmented-control";

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
  it("gives items stable ids when `id` is set, so a label can focus the checked item without renaming it", () => {
    render(
      <>
        <label htmlFor={segmentedItemId("acc", "read")}>Access</label>
        <SegmentedControl id="acc" aria-label="access" value="read" onChange={() => {}} options={opts} />
      </>,
    );
    const read = screen.getByRole("radio", { name: "read" });
    expect(read.id).toBe("acc-read");
    expect(screen.getByRole("radio", { name: "read-write" }).id).toBe("acc-read-write");
    expect((screen.getByText("Access") as HTMLLabelElement).control).toBe(read);
    // The native label did NOT become the radio's name.
    expect(screen.queryByRole("radio", { name: "Access" })).not.toBeInTheDocument();
  });
  it("renders no item ids without `id` (markup unchanged for other callers)", () => {
    render(<SegmentedControl aria-label="access" value="read" onChange={() => {}} options={opts} />);
    expect(screen.getByRole("radio", { name: "read" })).not.toHaveAttribute("id");
  });
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
  it("cannot be rendered without a name (type-level guard)", () => {
    // @ts-expect-error — neither aria-label nor aria-labelledby: must not compile.
    const unnamed = <SegmentedControl value="read" onChange={() => {}} options={opts} />;
    // @ts-expect-error — both at once is also refused: exactly one naming path.
    const both = <SegmentedControl aria-label="a" aria-labelledby="b" value="read" onChange={() => {}} options={opts} />;
    expect(unnamed).toBeTruthy();
    expect(both).toBeTruthy();
  });
});
