import { render, screen, fireEvent } from "@testing-library/react";
import { vi, it, expect } from "vitest";
import { EnforceToggle } from "../components/EnforceToggle";

it("reflects state and flips on click", () => {
  const onToggle = vi.fn();
  const { rerender } = render(<EnforceToggle enforcing={false} onToggle={onToggle} />);
  const sw = screen.getByRole("switch", { name: /enforce/i });
  expect(sw).not.toBeChecked();
  expect(screen.getByText("Firewall off")).toBeInTheDocument();
  fireEvent.click(sw);
  expect(onToggle).toHaveBeenCalledTimes(1);
  rerender(<EnforceToggle enforcing onToggle={onToggle} />);
  expect(screen.getByRole("switch", { name: /enforce/i })).toBeChecked();
  expect(screen.getByText("Firewall on")).toBeInTheDocument();
});

it("does not fire when disabled", () => {
  const onToggle = vi.fn();
  render(<EnforceToggle enforcing={false} disabled onToggle={onToggle} />);
  fireEvent.click(screen.getByRole("switch", { name: /enforce/i }));
  expect(onToggle).not.toHaveBeenCalled();
});
