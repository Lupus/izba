import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { Detail } from "../components/Detail";
import type { SandboxView } from "../lib/types";

describe("Detail", () => {
  it("prompts to select when no sandbox is given", () => {
    render(<Detail sandbox={null} />);
    expect(screen.getByText(/select a sandbox/i)).toBeInTheDocument();
  });

  it("shows name and image for a sandbox", () => {
    const sbx: SandboxView = { name: "web", image: "ubuntu:24.04", state: { kind: "running" } };
    render(<Detail sandbox={sbx} />);
    expect(screen.getByText("web")).toBeInTheDocument();
    expect(screen.getByText("ubuntu:24.04")).toBeInTheDocument();
  });

  it("surfaces the degraded reason", () => {
    const sbx: SandboxView = {
      name: "api",
      image: "node:20",
      state: { kind: "degraded", reason: "sidecar virtiofsd:workspace died" },
    };
    render(<Detail sandbox={sbx} />);
    expect(screen.getByText("sidecar virtiofsd:workspace died")).toBeInTheDocument();
  });
});
