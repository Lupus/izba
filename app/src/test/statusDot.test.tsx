import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { StatusDot } from "../components/StatusDot";

describe("StatusDot", () => {
  it("renders running with an accessible label", () => {
    render(<StatusDot state={{ kind: "running" }} />);
    expect(screen.getByLabelText("running")).toBeInTheDocument();
  });
  it("renders degraded reason in the label", () => {
    render(<StatusDot state={{ kind: "degraded", reason: "sidecar virtiofsd:workspace died" }} />);
    expect(screen.getByLabelText(/sidecar virtiofsd:workspace died/)).toBeInTheDocument();
  });
});
