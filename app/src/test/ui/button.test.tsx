import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { Button, buttonVariants } from "@/components/ui/button";

describe("Button", () => {
  it("renders a <button> with children", () => {
    render(<Button>Save</Button>);
    expect(screen.getByRole("button", { name: "Save" })).toBeInTheDocument();
  });
  it("fires onClick", () => {
    const onClick = vi.fn();
    render(<Button onClick={onClick}>Go</Button>);
    fireEvent.click(screen.getByRole("button", { name: "Go" }));
    expect(onClick).toHaveBeenCalledOnce();
  });
  it("honors disabled", () => {
    render(<Button disabled>Nope</Button>);
    expect(screen.getByRole("button", { name: "Nope" })).toBeDisabled();
  });
  it("maps the destructive variant to the destructive token (single source of truth)", () => {
    expect(buttonVariants({ variant: "destructive" })).toContain("destructive");
  });
  it("default variant is primary", () => {
    expect(buttonVariants({})).toContain("bg-primary");
  });
  it("renders as child element when asChild", () => {
    render(<Button asChild><a href="/x">link</a></Button>);
    const link = screen.getByRole("link", { name: "link" });
    expect(link).toHaveClass("bg-primary");
  });
});
