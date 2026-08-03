import { render, screen } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach } from "vitest";
import type { SandboxDetail } from "../lib/types";
import { containerLabel } from "../lib/container";

// ── hoisted mocks ────────────────────────────────────────────────────────────

const { inspect } = vi.hoisted(() => ({ inspect: vi.fn() }));

vi.mock("../lib/ipc", () => ({
  api: { inspect },
}));

import { ContainerStatus } from "../components/ContainerStatus";

// ── helpers ──────────────────────────────────────────────────────────────────

function detail(container: string | null): SandboxDetail {
  return {
    name: "web",
    image: "ubuntu:24.04",
    status: "running",
    workspace: "/ws",
    ports: [],
    volumes: [],
    container,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("containerLabel", () => {
  it("mirrors the CLI label set", () => {
    expect(containerLabel("running")).toBe("running");
    expect(containerLabel("stopped")).toBe("stopped (workload exited)");
    expect(containerLabel("created")).toBe("created (not started)");
    expect(containerLabel("creating")).toBe("creating");
    expect(containerLabel("paused")).toBe("paused");
  });

  it("never implies healthy for null, unknown, or unrecognized tokens", () => {
    expect(containerLabel(null)).toBe("unknown");
    expect(containerLabel("unknown")).toBe("unknown");
    expect(containerLabel("gibberish")).toBe("unknown");
  });
});

describe("ContainerStatus", () => {
  it("renders a running container", async () => {
    inspect.mockResolvedValue(detail("running"));
    render(<ContainerStatus name="web" />);
    expect(await screen.findByText("running")).toBeInTheDocument();
    expect(inspect).toHaveBeenCalledWith("web");
  });

  it("renders an exited workload honestly", async () => {
    inspect.mockResolvedValue(detail("stopped"));
    render(<ContainerStatus name="web" />);
    expect(await screen.findByText("stopped (workload exited)")).toBeInTheDocument();
  });

  it("renders null container state as unknown, never healthy", async () => {
    inspect.mockResolvedValue(detail(null));
    render(<ContainerStatus name="web" />);
    expect(await screen.findByText("unknown")).toBeInTheDocument();
  });

  it("renders nothing while inspect is unresolved or failed", async () => {
    inspect.mockRejectedValue(new Error("daemon restarting"));
    const { container } = render(<ContainerStatus name="web" />);
    // Best-effort like WorkspacePath: a failed inspect leaves no line behind.
    await vi.waitFor(() => expect(inspect).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
  });
});
