import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { Card, CardTitle, CardContent } from "@/components/ui/card";
import { Badge, badgeVariants } from "@/components/ui/badge";

describe("Card + Badge", () => {
  it("renders card title and content", () => {
    render(<Card><CardTitle>Storage</CardTitle><CardContent>body</CardContent></Card>);
    expect(screen.getByText("Storage")).toBeInTheDocument();
    expect(screen.getByText("body")).toBeInTheDocument();
  });
  it("card uses the card surface token", () => {
    const { container } = render(<Card>x</Card>);
    expect(container.firstChild).toHaveClass("bg-card");
  });
  it("warning badge maps to the destructive/warn token", () => {
    expect(badgeVariants({ variant: "warning" })).toContain("destructive");
  });
  it("renders badge text", () => {
    render(<Badge>persistent</Badge>);
    expect(screen.getByText("persistent")).toBeInTheDocument();
  });
});
