import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";

import { Meter } from "../../components/overview/Meter";

function fill(): HTMLElement {
  const meter = screen.getByRole("meter");
  return meter.firstElementChild as HTMLElement;
}

describe("Meter", () => {
  it("uses the ok tone below the warn threshold", () => {
    render(<Meter fraction={0.5} label="CPU usage" />);
    expect(fill().className).toContain("bg-success");
  });

  it("uses the warn tone at 80% and above", () => {
    render(<Meter fraction={0.85} label="CPU usage" />);
    expect(fill().className).toContain("bg-warning");
  });

  it("uses the crit tone at 95% and above", () => {
    render(<Meter fraction={0.97} label="CPU usage" />);
    expect(fill().className).toContain("bg-destructive");
  });

  it("renders the fraction as a percentage width and exposes it to a11y", () => {
    render(<Meter fraction={0.5} label="CPU usage" />);
    const meter = screen.getByRole("meter", { name: "CPU usage" });
    expect(meter).toHaveAttribute("aria-valuenow", "50");
    expect(meter).toHaveAttribute("aria-valuemin", "0");
    expect(meter).toHaveAttribute("aria-valuemax", "100");
    expect(fill().style.width).toBe("50%");
  });

  it("clamps an over-limit fraction to 100%", () => {
    render(<Meter fraction={1.4} label="MEM usage" />);
    expect(fill().style.width).toBe("100%");
    expect(screen.getByRole("meter")).toHaveAttribute("aria-valuenow", "100");
  });
});
