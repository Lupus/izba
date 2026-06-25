import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { Checkbox } from "@/components/ui/checkbox";

describe("Checkbox", () => {
  it("renders a checkbox and calls onCheckedChange with true when clicked while unchecked", () => {
    const onCheckedChange = vi.fn();
    render(<Checkbox aria-label="pick" checked={false} onCheckedChange={onCheckedChange} />);
    const checkbox = screen.getByRole("checkbox", { name: "pick" });
    expect(checkbox).toBeTruthy();
    fireEvent.click(checkbox);
    expect(onCheckedChange).toHaveBeenCalledWith(true);
  });
});
