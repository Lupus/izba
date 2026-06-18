import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { Rail } from "../components/Rail";
import type { SandboxView } from "../lib/types";

const sandboxes: SandboxView[] = [
  { name: "web", image: "ubuntu:24.04", state: { kind: "running" } },
  { name: "db", image: "postgres:16", state: { kind: "stopped" } },
];

const defaultView = "sandboxes" as const;
const noop = () => {};

describe("Rail", () => {
  it("lists sandbox names and images", () => {
    render(
      <Rail
        sandboxes={sandboxes}
        selected="web"
        onSelect={noop}
        onNew={noop}
        view={defaultView}
        onView={noop}
      />,
    );
    expect(screen.getByText("web")).toBeInTheDocument();
    expect(screen.getByText("postgres:16")).toBeInTheDocument();
  });

  it("calls onSelect when a sandbox is clicked", () => {
    const onSelect = vi.fn();
    render(
      <Rail
        sandboxes={sandboxes}
        selected="web"
        onSelect={onSelect}
        onNew={noop}
        view={defaultView}
        onView={noop}
      />,
    );
    fireEvent.click(screen.getByText("db"));
    expect(onSelect).toHaveBeenCalledWith("db");
  });

  it("marks the selected sandbox as pressed", () => {
    render(
      <Rail
        sandboxes={sandboxes}
        selected="web"
        onSelect={noop}
        onNew={noop}
        view={defaultView}
        onView={noop}
      />,
    );
    expect(screen.getByText("web").closest("button")).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByText("db").closest("button")).toHaveAttribute("aria-pressed", "false");
  });

  it("has an enabled New sandbox button that calls onNew", () => {
    const onNew = vi.fn();
    render(
      <Rail
        sandboxes={[]}
        selected={null}
        onSelect={noop}
        onNew={onNew}
        view={defaultView}
        onView={noop}
      />,
    );
    const btn = screen.getByRole("button", { name: /new sandbox/i });
    expect(btn).toBeEnabled();
    fireEvent.click(btn);
    expect(onNew).toHaveBeenCalledOnce();
  });

  it("renders a Storage nav button with aria-pressed=false when view is sandboxes", () => {
    render(
      <Rail
        sandboxes={sandboxes}
        selected={null}
        onSelect={noop}
        onNew={noop}
        view="sandboxes"
        onView={noop}
      />,
    );
    const storageBtn = screen.getByRole("button", { name: /storage/i });
    expect(storageBtn).toHaveAttribute("aria-pressed", "false");
  });

  it("renders Storage nav button with aria-pressed=true when view is storage", () => {
    render(
      <Rail
        sandboxes={sandboxes}
        selected={null}
        onSelect={noop}
        onNew={noop}
        view="storage"
        onView={noop}
      />,
    );
    const storageBtn = screen.getByRole("button", { name: /storage/i });
    expect(storageBtn).toHaveAttribute("aria-pressed", "true");
  });

  it("calls onView('storage') when Storage button is clicked", () => {
    const onView = vi.fn();
    render(
      <Rail
        sandboxes={sandboxes}
        selected={null}
        onSelect={noop}
        onNew={noop}
        view="sandboxes"
        onView={onView}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: /storage/i }));
    expect(onView).toHaveBeenCalledWith("storage");
  });

  it("calls onView('sandboxes') when a sandbox button is clicked", () => {
    const onView = vi.fn();
    render(
      <Rail
        sandboxes={sandboxes}
        selected={null}
        onSelect={noop}
        onNew={noop}
        view="storage"
        onView={onView}
      />,
    );
    fireEvent.click(screen.getByText("web"));
    expect(onView).toHaveBeenCalledWith("sandboxes");
  });
});
