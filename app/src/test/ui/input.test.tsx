import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

describe("Input", () => {
  it("renders and accepts typing", () => {
    const onChange = vi.fn();
    render(<Input placeholder="name" onChange={onChange} />);
    const el = screen.getByPlaceholderText("name");
    fireEvent.change(el, { target: { value: "web" } });
    expect(onChange).toHaveBeenCalled();
  });
  it("honors disabled", () => {
    render(<Input placeholder="p" disabled />);
    expect(screen.getByPlaceholderText("p")).toBeDisabled();
  });
  it("uses the border token", () => {
    render(<Input placeholder="p" />);
    expect(screen.getByPlaceholderText("p").className).toContain("border-input");
  });
  it("Label associates with a control", () => {
    render(<><Label htmlFor="x">Name</Label><Input id="x" /></>);
    expect(screen.getByText("Name")).toHaveAttribute("for", "x");
  });
});
