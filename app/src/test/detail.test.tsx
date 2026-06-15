import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { Detail } from "../components/Detail";
import type { SandboxView } from "../lib/types";

vi.mock("../lib/ipc", () => ({
  api: {
    start: vi.fn().mockResolvedValue(undefined),
    stop: vi.fn().mockResolvedValue(undefined),
    restart: vi.fn().mockResolvedValue(undefined),
    remove: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock("../components/LogsView", () => ({
  LogsView: ({ name }: { name: string }) => <div>logs-for-{name}</div>,
}));
vi.mock("../components/ShellPanel", () => ({
  ShellPanel: ({ sandbox }: { sandbox: string }) => <div>shell-for-{sandbox}</div>,
}));

const noop = () => {};

describe("Detail", () => {
  it("prompts to select when no sandbox is given", () => {
    render(<Detail sandbox={null} onChanged={noop} />);
    expect(screen.getByText(/select a sandbox/i)).toBeInTheDocument();
  });

  it("shows name and image for a sandbox", () => {
    const sbx: SandboxView = { name: "web", image: "ubuntu:24.04", state: { kind: "running" } };
    render(<Detail sandbox={sbx} onChanged={noop} />);
    expect(screen.getByText("web")).toBeInTheDocument();
    expect(screen.getByText("ubuntu:24.04")).toBeInTheDocument();
  });

  it("surfaces the degraded reason", () => {
    const sbx: SandboxView = {
      name: "api",
      image: "node:20",
      state: { kind: "degraded", reason: "sidecar virtiofsd:workspace died" },
    };
    render(<Detail sandbox={sbx} onChanged={noop} />);
    expect(screen.getByText("sidecar virtiofsd:workspace died")).toBeInTheDocument();
  });
});

describe("Detail actions", () => {
  beforeEach(() => vi.clearAllMocks());

  it("shows Start for a stopped sandbox and calls api.start + onChanged", async () => {
    const { api } = await import("../lib/ipc");
    const onChanged = vi.fn();
    const sbx: SandboxView = { name: "db", image: "postgres:16", state: { kind: "stopped" } };
    render(<Detail sandbox={sbx} onChanged={onChanged} />);
    fireEvent.click(screen.getByRole("button", { name: /^start$/i }));
    await waitFor(() => expect(api.start).toHaveBeenCalledWith("db"));
    await waitFor(() => expect(onChanged).toHaveBeenCalled());
  });

  it("confirms before stopping a running sandbox", async () => {
    const { api } = await import("../lib/ipc");
    const sbx: SandboxView = { name: "web", image: "ubuntu:24.04", state: { kind: "running" } };
    render(<Detail sandbox={sbx} onChanged={noop} />);
    fireEvent.click(screen.getByRole("button", { name: /^stop$/i }));
    expect(api.stop).not.toHaveBeenCalled(); // not until confirmed
    const dialog = screen.getByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: /^stop$/i }));
    await waitFor(() => expect(api.stop).toHaveBeenCalledWith("web"));
  });

  it("Remove requires confirmation then calls api.remove", async () => {
    const { api } = await import("../lib/ipc");
    const sbx: SandboxView = { name: "web", image: "ubuntu:24.04", state: { kind: "running" } };
    render(<Detail sandbox={sbx} onChanged={noop} />);
    fireEvent.click(screen.getByRole("button", { name: /^remove$/i }));
    expect(api.remove).not.toHaveBeenCalled();
    const dialog = screen.getByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: /^remove$/i }));
    await waitFor(() => expect(api.remove).toHaveBeenCalledWith("web", false));
  });
});

describe("Detail tabs", () => {
  beforeEach(() => vi.clearAllMocks());

  it("defaults to Overview and shows lifecycle actions", () => {
    const sbx: SandboxView = { name: "web", image: "ubuntu:24.04", state: { kind: "running" } };
    render(<Detail sandbox={sbx} onChanged={noop} />);
    expect(screen.getByRole("button", { name: /^stop$/i })).toBeInTheDocument();
  });

  it("switches to the Logs tab", () => {
    const sbx: SandboxView = { name: "web", image: "ubuntu:24.04", state: { kind: "running" } };
    render(<Detail sandbox={sbx} onChanged={noop} />);
    fireEvent.click(screen.getByRole("tab", { name: /logs/i }));
    expect(screen.getByText("logs-for-web")).toBeInTheDocument();
  });

  it("shows the shell for a running sandbox and a hint when stopped", () => {
    const running: SandboxView = { name: "web", image: "ubuntu:24.04", state: { kind: "running" } };
    const { rerender } = render(<Detail sandbox={running} onChanged={noop} />);
    fireEvent.click(screen.getByRole("tab", { name: /shell/i }));
    expect(screen.getByText("shell-for-web")).toBeInTheDocument();

    const stopped: SandboxView = { name: "db", image: "postgres:16", state: { kind: "stopped" } };
    rerender(<Detail sandbox={stopped} onChanged={noop} />);
    fireEvent.click(screen.getByRole("tab", { name: /shell/i }));
    expect(screen.getByText(/start the sandbox/i)).toBeInTheDocument();
  });
});
