import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { Switch } from "@/components/ui/switch";

describe("Switch", () => {
  it("renders a switch and toggles", () => {
    const onCheckedChange = vi.fn();
    render(<Switch aria-label="enforce" checked={false} onCheckedChange={onCheckedChange} />);
    fireEvent.click(screen.getByRole("switch", { name: "enforce" }));
    expect(onCheckedChange).toHaveBeenCalledWith(true);
  });
});
