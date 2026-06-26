import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { EditableList } from "@/components/ui/editable-list";

describe("EditableList", () => {
  it("shows the empty hint + add button when there are no items", () => {
    render(
      <EditableList
        items={[]}
        renderRow={() => null}
        onAdd={() => {}}
        onRemove={() => {}}
        addLabel="Add forward"
        emptyHint="No forwards — add one to publish a port"
      />,
    );
    expect(screen.getByText(/No forwards/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Add forward" })).toBeInTheDocument();
  });

  it("fires onAdd when the add button is clicked", () => {
    const onAdd = vi.fn();
    render(
      <EditableList items={[]} renderRow={() => null} onAdd={onAdd} onRemove={() => {}}
        addLabel="Add host" emptyHint="none" />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Add host" }));
    expect(onAdd).toHaveBeenCalledOnce();
  });

  it("renders a row per item with the fields and a remove button; fires onRemove(index)", () => {
    const onRemove = vi.fn();
    render(
      <EditableList
        items={["a", "b"]}
        renderRow={(item) => <span>row-{item}</span>}
        onAdd={() => {}}
        onRemove={onRemove}
        addLabel="Add"
        emptyHint="none"
        rowAriaLabel={(_, i) => `Remove row ${i + 1}`}
      />,
    );
    expect(screen.getByText("row-a")).toBeInTheDocument();
    expect(screen.getByText("row-b")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Remove row 2" }));
    expect(onRemove).toHaveBeenCalledWith(1);
  });

  it("card density wraps each row in a bordered RowCard; inline does not", () => {
    const { rerender } = render(
      <EditableList items={["a"]} renderRow={() => <span>x</span>} onAdd={() => {}}
        onRemove={() => {}} addLabel="Add" emptyHint="none" density="card" />,
    );
    expect(screen.getByText("x").closest(".rounded-lg.border")).not.toBeNull();
    rerender(
      <EditableList items={["a"]} renderRow={() => <span>y</span>} onAdd={() => {}}
        onRemove={() => {}} addLabel="Add" emptyHint="none" density="inline" />,
    );
    expect(screen.getByText("y").closest(".rounded-lg.border")).toBeNull();
  });
});
