import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from "@/components/ui/select";

describe("Select", () => {
  it("renders a combobox trigger with the placeholder", () => {
    render(
      <Select>
        <SelectTrigger aria-label="kind"><SelectValue placeholder="pick" /></SelectTrigger>
        <SelectContent>
          <SelectItem value="a">A</SelectItem>
        </SelectContent>
      </Select>,
    );
    expect(screen.getByRole("combobox", { name: "kind" })).toBeInTheDocument();
    expect(screen.getByText("pick")).toBeInTheDocument();
  });
});
