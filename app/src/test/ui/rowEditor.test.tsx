import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { RowList, RowCard, AddRowButton, RemoveRowButton } from "@/components/ui/row-editor";

describe("RowEditor", () => {
  it("AddRowButton fires onClick and renders its label", () => {
    const onClick = vi.fn();
    render(<AddRowButton onClick={onClick}>Add volume</AddRowButton>);
    fireEvent.click(screen.getByRole("button", { name: "Add volume" }));
    expect(onClick).toHaveBeenCalledOnce();
  });
  it("AddRowButton renders a leading Plus icon and a solid (non-transparent) surface", () => {
    const { container } = render(<AddRowButton onClick={() => {}}>Add volume</AddRowButton>);
    const btn = screen.getByRole("button", { name: "Add volume" });
    // solid, surface-independent background (not bg-transparent)
    expect(btn.className).toContain("bg-card");
    expect(btn.className).not.toContain("bg-transparent");
    // leading icon present (lucide renders an <svg>)
    expect(container.querySelector("svg")).toBeInTheDocument();
    // never stretches full-width: self-start (flex parent) + justify-self-start
    // (grid parent, e.g. PortsTab's create-form) so it stays content-width.
    expect(btn.className).toContain("self-start");
    expect(btn.className).toContain("justify-self-start");
  });
  it("RemoveRowButton is destructive-styled and labelled", () => {
    const onClick = vi.fn();
    render(<RemoveRowButton aria-label="remove" onClick={onClick} />);
    const btn = screen.getByRole("button", { name: "remove" });
    expect(btn.className).toContain("destructive");
    fireEvent.click(btn);
    expect(onClick).toHaveBeenCalledOnce();
  });
  it("RowList + RowCard render children", () => {
    render(<RowList><RowCard>row-1</RowCard></RowList>);
    expect(screen.getByText("row-1")).toBeInTheDocument();
  });
});
