import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { AccessPicker } from "../components/AccessPicker";

describe("AccessPicker", () => {
  it("defaults its accessible name to 'access' (SeedDialog relies on this)", () => {
    render(<AccessPicker value="read" onChange={() => {}} />);
    expect(screen.getByRole("radiogroup", { name: "access" })).toBeInTheDocument();
  });

  it("takes an aria-label override", () => {
    render(<AccessPicker value="read" onChange={() => {}} aria-label="Access for git rule 1 (github.com/o/a)" />);
    expect(screen.getByRole("radiogroup", { name: "Access for git rule 1 (github.com/o/a)" })).toBeInTheDocument();
    expect(screen.queryByRole("radiogroup", { name: "access" })).not.toBeInTheDocument();
  });

  it("takes aria-labelledby, and then renders no aria-label at all", () => {
    render(
      <>
        <span id="lbl">Access</span>
        <span id="rule">for host rule 2 (db.internal)</span>
        <AccessPicker value="read-write" onChange={() => {}} aria-labelledby="lbl rule" />
      </>,
    );
    const group = screen.getByRole("radiogroup", { name: "Access for host rule 2 (db.internal)" });
    expect(group).not.toHaveAttribute("aria-label");
  });
});
