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
