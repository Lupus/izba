import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach } from "vitest";
import type { UsbDevice, UsbUpstream } from "../lib/types";

// ── hoisted mocks ────────────────────────────────────────────────────────────

const { usbUpstreamShow, usbUpstreamSet, usbListDevices } = vi.hoisted(() => ({
  usbUpstreamShow: vi.fn(),
  usbUpstreamSet: vi.fn(),
  usbListDevices: vi.fn(),
}));

vi.mock("../lib/ipc", () => ({
  api: { usbUpstreamShow, usbUpstreamSet, usbListDevices },
}));

import { UsbView } from "../components/UsbView";

// ── fixtures ─────────────────────────────────────────────────────────────────

const upstream: UsbUpstream = {
  host: "127.0.0.1",
  port: 3240,
  resolved: "127.0.0.1",
  trust: "own-host-loopback",
  warning: null,
};

const shared: UsbDevice = {
  busid: "3-2",
  device: "0403:6001",
  description: "FT232 USB UART",
  shared: true,
  granted_to: ["web"],
  attached_to: "web",
  bind_command: null,
};

const unshared: UsbDevice = {
  busid: "1-4",
  device: "10c4:ea60",
  description: "CP2102",
  shared: false,
  granted_to: [],
  attached_to: null,
  bind_command: "usbipd bind --busid 1-4",
};

beforeEach(() => {
  vi.clearAllMocks();
  usbUpstreamShow.mockResolvedValue(upstream);
  usbListDevices.mockResolvedValue([shared, unshared]);
  usbUpstreamSet.mockResolvedValue(undefined);
});

// ── tests ────────────────────────────────────────────────────────────────────

describe("UsbView", () => {
  it("does not enumerate devices when USB is not configured", async () => {
    usbUpstreamShow.mockResolvedValue(null);
    render(<UsbView />);
    await screen.findByText(/not configured/i);
    // Every other USB RPC refuses with the feature off; calling one to discover
    // that would render a scary error for an entirely ordinary state.
    expect(usbListDevices).not.toHaveBeenCalled();
  });

  it("shows the trust warning loudly for a non-loopback upstream", async () => {
    usbUpstreamShow.mockResolvedValue({
      ...upstream,
      host: "192.168.1.9",
      trust: "private-lan",
      warning: "anyone who can route there can attach the same devices",
    });
    render(<UsbView />);
    await screen.findByText(/anyone who can route there/i);
    expect(screen.getByText("private-lan")).toBeInTheDocument();
  });

  it("stays quiet about trust for the recommended loopback upstream", async () => {
    render(<UsbView />);
    await screen.findByText("0403:6001");
    expect(screen.queryByText(/anyone who can route/i)).not.toBeInTheDocument();
  });

  it("names the sandbox holding a device and the ones granted it", async () => {
    render(<UsbView />);
    await screen.findByText("0403:6001");
    expect(screen.getByText(/attached to web/i)).toBeInTheDocument();
    expect(screen.getByText(/granted to web/i)).toBeInTheDocument();
  });

  it("offers the bind command for an unshared device and never runs it", async () => {
    render(<UsbView />);
    await screen.findByText("usbipd bind --busid 1-4");
    // Copy-only by design: no button may claim to share the device, because
    // that would need Administrator on the USB host.
    expect(screen.queryByRole("button", { name: /^share$/i })).not.toBeInTheDocument();
    expect(screen.getByText(/never runs this for you/i)).toBeInTheDocument();
  });

  it("copies the bind command to the clipboard", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, { clipboard: { writeText } });
    render(<UsbView />);
    fireEvent.click(await screen.findByRole("button", { name: /copy the share command/i }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith("usbipd bind --busid 1-4"));
  });

  it("says so when the clipboard refuses instead of failing silently", async () => {
    const writeText = vi.fn().mockRejectedValue(new Error("denied"));
    Object.assign(navigator, { clipboard: { writeText } });
    render(<UsbView />);
    fireEvent.click(await screen.findByRole("button", { name: /copy the share command/i }));
    await screen.findByText(/copy it manually/i);
  });

  it("saves a new upstream and reloads", async () => {
    render(<UsbView />);
    await screen.findByText("0403:6001");
    fireEvent.click(screen.getByRole("button", { name: /change/i }));
    fireEvent.change(screen.getByLabelText(/^host$/i), { target: { value: "172.20.0.1" } });
    fireEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() => expect(usbUpstreamSet).toHaveBeenCalledWith("172.20.0.1", 3240, false));
  });

  it("passes the remote opt-in through when it is ticked", async () => {
    usbUpstreamShow.mockResolvedValue(null);
    render(<UsbView />);
    fireEvent.click(await screen.findByRole("button", { name: /configure upstream/i }));
    fireEvent.change(screen.getByLabelText(/^host$/i), { target: { value: "203.0.113.7" } });
    fireEvent.click(screen.getByLabelText(/globally routable/i));
    fireEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() => expect(usbUpstreamSet).toHaveBeenCalledWith("203.0.113.7", 3240, true));
  });

  it("rejects a nonsense port before calling the daemon", async () => {
    usbUpstreamShow.mockResolvedValue(null);
    render(<UsbView />);
    fireEvent.click(await screen.findByRole("button", { name: /configure upstream/i }));
    fireEvent.change(screen.getByLabelText(/^host$/i), { target: { value: "127.0.0.1" } });
    fireEvent.change(screen.getByLabelText(/^port$/i), { target: { value: "99999" } });
    fireEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await screen.findByText(/between 1 and 65535/i);
    expect(usbUpstreamSet).not.toHaveBeenCalled();
  });

  it("shows an unreachable upstream as an error rather than an empty list", async () => {
    usbListDevices.mockRejectedValue(new Error("connection refused"));
    render(<UsbView />);
    await screen.findByText(/connection refused/i);
  });
});
