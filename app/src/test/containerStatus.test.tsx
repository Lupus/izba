import { render, screen, waitFor } from "@testing-library/react";
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
    docker: false,
    cpus: 2,
    mem_mb: 4096,
    confinement: null,
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

  it("re-polls so a workload exiting while mounted flips the label", async () => {
    inspect.mockResolvedValue(detail("running"));
    render(<ContainerStatus name="web" pollMs={20} />);
    expect(await screen.findByText("running")).toBeInTheDocument();

    // The workload exits; `name` never changes — the next poll must notice.
    inspect.mockResolvedValue(detail("stopped"));
    expect(await screen.findByText("stopped (workload exited)")).toBeInTheDocument();
  });

  it("drops the line instead of keeping a stale claim when inspect starts failing", async () => {
    inspect.mockResolvedValue(detail("running"));
    const { container } = render(<ContainerStatus name="web" pollMs={20} />);
    expect(await screen.findByText("running")).toBeInTheDocument();

    inspect.mockRejectedValue(new Error("daemon restarting"));
    await waitFor(() => expect(container).toBeEmptyDOMElement());
  });

  it("skips overlapping polls so an older reply can never overwrite a fresher one", async () => {
    let resolveFirst!: (d: SandboxDetail) => void;
    inspect.mockImplementationOnce(
      () => new Promise<SandboxDetail>((r) => (resolveFirst = r)),
    );
    inspect.mockResolvedValue(detail("stopped"));
    render(<ContainerStatus name="web" pollMs={20} />);

    // The first probe hangs across several poll intervals: overlapping ticks
    // are skipped, not raced — no second request goes out.
    await waitFor(() => expect(inspect).toHaveBeenCalledTimes(1));
    await new Promise((r) => setTimeout(r, 70));
    expect(inspect).toHaveBeenCalledTimes(1);

    resolveFirst(detail("running"));
    expect(await screen.findByText("running")).toBeInTheDocument();

    // With the slow probe settled, the next tick fetches the fresh state.
    expect(await screen.findByText("stopped (workload exited)")).toBeInTheDocument();
  });

  it("times out a hung probe so polling recovers instead of stalling forever", async () => {
    // First probe never settles (live VM accepts the health request but never
    // answers). The timeout must hide the line and let later polls proceed.
    inspect.mockImplementationOnce(() => new Promise<SandboxDetail>(() => {}));
    inspect.mockResolvedValue(detail("stopped"));
    const { container } = render(
      <ContainerStatus name="web" pollMs={20} probeTimeoutMs={50} />,
    );

    await waitFor(() => expect(inspect).toHaveBeenCalledTimes(1));
    expect(container).toBeEmptyDOMElement();

    // After the probe times out, the next tick issues a fresh inspect and the
    // honest state lands.
    expect(await screen.findByText("stopped (workload exited)")).toBeInTheDocument();
    expect(inspect.mock.calls.length).toBeGreaterThan(1);
  });
});
