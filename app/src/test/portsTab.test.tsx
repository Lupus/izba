import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach } from "vitest";
import type { SandboxView, PortRule, SandboxDetail } from "../lib/types";

// ── hoisted mocks ────────────────────────────────────────────────────────────

const { portList, portPublish, portUnpublish, inspect } = vi.hoisted(() => ({
  portList: vi.fn(),
  portPublish: vi.fn(),
  portUnpublish: vi.fn(),
  inspect: vi.fn(),
}));

vi.mock("../lib/ipc", () => ({
  api: { portList, portPublish, portUnpublish, inspect },
}));

const { openUrl } = vi.hoisted(() => ({ openUrl: vi.fn() }));
vi.mock("@tauri-apps/plugin-opener", () => ({ openUrl }));

import { PortsTab } from "../components/PortsTab";

// ── helpers ──────────────────────────────────────────────────────────────────

const running: SandboxView = { name: "web", image: "ubuntu:24.04", state: { kind: "running" } };
const stopped: SandboxView = { name: "web", image: "ubuntu:24.04", state: { kind: "stopped" } };

const rule: PortRule = { bind: "127.0.0.1", host_port: 8080, guest_port: 80 };

function detail(ports: PortRule[] = []): SandboxDetail {
  return { name: "web", image: "ubuntu:24.04", status: "running", ports, volumes: [] };
}

beforeEach(() => {
  vi.clearAllMocks();
  portList.mockResolvedValue([]);
  inspect.mockResolvedValue(detail());
  portPublish.mockResolvedValue(undefined);
  portUnpublish.mockResolvedValue(undefined);
  openUrl.mockResolvedValue(undefined);
});

// ── tests ────────────────────────────────────────────────────────────────────

describe("PortsTab", () => {
  it("renders forwards from portList", async () => {
    portList.mockResolvedValue([rule]);
    inspect.mockResolvedValue(detail([rule])); // persisted
    render(<PortsTab sandbox={running} />);
    await screen.findByText(/127\.0\.0\.1:8080/);
    expect(screen.getByText(/127\.0\.0\.1:8080/)).toBeInTheDocument();
  });

  it("shows 'active until restart' badge and Make persistent for a live-only forward", async () => {
    portList.mockResolvedValue([rule]);
    inspect.mockResolvedValue(detail([])); // not persisted
    render(<PortsTab sandbox={running} />);
    await screen.findByText(/active until restart/i);
    expect(screen.getByRole("button", { name: /make persistent/i })).toBeInTheDocument();
  });

  it("does NOT show 'active until restart' for a persisted forward", async () => {
    portList.mockResolvedValue([rule]);
    inspect.mockResolvedValue(detail([rule])); // persisted
    render(<PortsTab sandbox={running} />);
    await screen.findByText(/127\.0\.0\.1:8080/);
    expect(screen.queryByText(/active until restart/i)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /make persistent/i })).not.toBeInTheDocument();
  });

  it("clicking Make persistent calls portPublish with persist=true then reloads", async () => {
    portList.mockResolvedValue([rule]);
    inspect.mockResolvedValue(detail([]));
    render(<PortsTab sandbox={running} />);
    const btn = await screen.findByRole("button", { name: /make persistent/i });
    fireEvent.click(btn);
    await waitFor(() =>
      expect(portPublish).toHaveBeenCalledWith("web", "127.0.0.1:8080:80", true),
    );
    // after making persistent, portList is re-fetched
    await waitFor(() => expect(portList).toHaveBeenCalledTimes(2));
  });

  it("clicking open-in-browser calls openUrl with http://127.0.0.1:<host_port>", async () => {
    portList.mockResolvedValue([rule]);
    inspect.mockResolvedValue(detail([rule]));
    render(<PortsTab sandbox={running} />);
    const btn = await screen.findByRole("button", { name: /open port 8080 in browser/i });
    fireEvent.click(btn);
    await waitFor(() => expect(openUrl).toHaveBeenCalledWith("http://127.0.0.1:8080"));
  });

  it("does NOT show open-in-browser for a persisted-only row (no live relay)", async () => {
    // portList is empty (sandbox stopped / no live relay), but inspect has a persisted rule
    portList.mockResolvedValue([]);
    inspect.mockResolvedValue(detail([rule]));
    render(<PortsTab sandbox={stopped} />);
    // Row is rendered (persisted)
    await screen.findByText(/127\.0\.0\.1:8080/);
    // But open-in-browser must NOT be shown because there is no live relay
    expect(screen.queryByRole("button", { name: /open port 8080 in browser/i })).not.toBeInTheDocument();
  });

  it("shows open-in-browser for a live forward even if sandbox appears running", async () => {
    portList.mockResolvedValue([rule]);
    inspect.mockResolvedValue(detail([rule]));
    render(<PortsTab sandbox={running} />);
    // Both persisted and live — must show open-in-browser
    await screen.findByRole("button", { name: /open port 8080 in browser/i });
  });

  it("clicking remove calls portUnpublish then reloads", async () => {
    portList.mockResolvedValue([rule]);
    inspect.mockResolvedValue(detail([rule]));
    render(<PortsTab sandbox={running} />);
    // find the remove button — aria-label includes the host port
    const btn = await screen.findByRole("button", { name: /remove port 8080/i });
    fireEvent.click(btn);
    await waitFor(() =>
      expect(portUnpublish).toHaveBeenCalledWith("web", "127.0.0.1", 8080),
    );
    await waitFor(() => expect(portList).toHaveBeenCalledTimes(2));
  });

  it("add-forward form is disabled when the sandbox is stopped, with a visible hint why", async () => {
    render(<PortsTab sandbox={stopped} />);
    // inputs and add button should be disabled
    await screen.findByLabelText(/host port/i);
    expect(screen.getByLabelText(/host port/i)).toBeDisabled();
    expect(screen.getByLabelText(/guest port/i)).toBeDisabled();
    expect(screen.getByRole("button", { name: /^add forward$/i })).toBeDisabled();
    // and the UI says why (same affordance as the Shell tab's stopped-state hint)
    expect(
      screen.getByText("Start the sandbox to add port forwards."),
    ).toBeInTheDocument();
  });

  it("add-forward form is enabled when the sandbox is running, without the stopped hint", async () => {
    render(<PortsTab sandbox={running} />);
    await screen.findByLabelText(/host port/i);
    expect(screen.getByLabelText(/host port/i)).not.toBeDisabled();
    expect(screen.getByLabelText(/guest port/i)).not.toBeDisabled();
    expect(screen.getByRole("button", { name: /^add forward$/i })).not.toBeDisabled();
    expect(
      screen.queryByText("Start the sandbox to add port forwards."),
    ).not.toBeInTheDocument();
  });

  it("submitting the add-forward form calls portPublish with persist=false", async () => {
    render(<PortsTab sandbox={running} />);
    await screen.findByLabelText(/host port/i);
    fireEvent.change(screen.getByLabelText(/host port/i), { target: { value: "9090" } });
    fireEvent.change(screen.getByLabelText(/guest port/i), { target: { value: "9090" } });
    fireEvent.click(screen.getByRole("button", { name: /^add forward$/i }));
    await waitFor(() =>
      expect(portPublish).toHaveBeenCalledWith("web", "9090:9090", false),
    );
  });

  it("submitting with a bind prefixes the rule string", async () => {
    render(<PortsTab sandbox={running} />);
    await screen.findByLabelText(/bind address/i);
    fireEvent.change(screen.getByLabelText(/bind address/i), { target: { value: "0.0.0.0" } });
    fireEvent.change(screen.getByLabelText(/host port/i), { target: { value: "8080" } });
    fireEvent.change(screen.getByLabelText(/guest port/i), { target: { value: "80" } });
    fireEvent.click(screen.getByRole("button", { name: /^add forward$/i }));
    await waitFor(() =>
      expect(portPublish).toHaveBeenCalledWith("web", "0.0.0.0:8080:80", false),
    );
  });
});
