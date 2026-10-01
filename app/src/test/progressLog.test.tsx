import { render, screen } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { ProgressLog } from "../components/ProgressLog";

describe("ProgressLog", () => {
  it("renders nothing until there is progress", () => {
    const { container } = render(<ProgressLog lines={[]} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("shows a repeated message once per occurrence, without key collisions", () => {
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    render(<ProgressLog lines={["retrying", "verifying", "retrying"]} />);
    expect(screen.getAllByText("retrying")).toHaveLength(2);
    expect(screen.getByText("verifying")).toBeInTheDocument();
    expect(err).not.toHaveBeenCalled();
    err.mockRestore();
  });
});
