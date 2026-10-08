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
