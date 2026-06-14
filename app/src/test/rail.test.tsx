import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { Rail } from "../components/Rail";
import type { SandboxView } from "../lib/types";

const sandboxes: SandboxView[] = [
  { name: "web", image: "ubuntu:24.04", state: { kind: "running" } },
  { name: "db", image: "postgres:16", state: { kind: "stopped" } },
];

describe("Rail", () => {
  it("lists sandbox names and images", () => {
    render(<Rail sandboxes={sandboxes} selected="web" onSelect={() => {}} />);
    expect(screen.getByText("web")).toBeInTheDocument();
    expect(screen.getByText("postgres:16")).toBeInTheDocument();
  });

  it("calls onSelect when a sandbox is clicked", () => {
    const onSelect = vi.fn();
    render(<Rail sandboxes={sandboxes} selected="web" onSelect={onSelect} />);
    fireEvent.click(screen.getByText("db"));
    expect(onSelect).toHaveBeenCalledWith("db");
  });
});
