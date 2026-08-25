import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach } from "vitest";
import type { UsbDevice, UsbGrant, UsbStatus, UsbUpstream } from "../lib/types";

// ── hoisted mocks ────────────────────────────────────────────────────────────

const m = vi.hoisted(() => ({
  usbUpstreamShow: vi.fn(),
  usbListDevices: vi.fn(),
  usbStatus: vi.fn(),
  usbAllow: vi.fn(),
  usbRevoke: vi.fn(),
  usbAttach: vi.fn(),
  usbDetach: vi.fn(),
  restart: vi.fn(),
}));

vi.mock("../lib/ipc", () => ({ api: m }));

import { UsbTab } from "../components/UsbTab";

// ── fixtures ─────────────────────────────────────────────────────────────────

const upstream: UsbUpstream = {
  host: "127.0.0.1",
  port: 3240,
  resolved: "127.0.0.1",
  trust: "own-host-loopback",
  warning: null,
};

const device: UsbDevice = {
  busid: "3-2",
  device: "0403:6001",
  description: "FT232 USB UART",
  shared: true,
  granted_to: [],
  attached_to: null,
  bind_command: null,
};

const grant: UsbGrant = {
  device: "0403:6001",
  busid_pin: null,
  description: "FT232 USB UART",
  granted_at_unix_ms: 1,
  attached: false,
};

const status = (over: Partial<UsbStatus> = {}): UsbStatus => ({
  grants: [],
  restart_required: false,
  ...over,
});

beforeEach(() => {
  vi.clearAllMocks();
  m.usbUpstreamShow.mockResolvedValue(upstream);
  m.usbListDevices.mockResolvedValue([device]);
  m.usbStatus.mockResolvedValue(status());
  for (const f of [m.usbAllow, m.usbRevoke, m.usbAttach, m.usbDetach, m.restart]) {
    f.mockResolvedValue(undefined);
  }
});

// ── tests ────────────────────────────────────────────────────────────────────

describe("UsbTab", () => {
  it("says USB is not configured and asks for nothing else", async () => {
    m.usbUpstreamShow.mockResolvedValue(null);
    render(<UsbTab name="web" running onChanged={() => {}} />);
    await screen.findByText(/not configured/i);
    expect(m.usbStatus).not.toHaveBeenCalled();
    expect(m.usbListDevices).not.toHaveBeenCalled();
  });

  it("grants only after the consent dialog is satisfied", async () => {
    render(<UsbTab name="web" running onChanged={() => {}} />);
    fireEvent.click(await screen.findByRole("button", { name: /allow 0403:6001/i }));
    // The dialog is the CLI's gate: opening it grants nothing.
    expect(m.usbAllow).not.toHaveBeenCalled();

    fireEvent.change(screen.getByLabelText(/type the device id/i), {
      target: { value: "0403:6001" },
    });
    fireEvent.click(screen.getByRole("button", { name: /^grant$/i }));
    await waitFor(() => expect(m.usbAllow).toHaveBeenCalledWith("web", "0403:6001", null));
  });

  it("warns that a restart is needed and does not offer attach", async () => {
    m.usbStatus.mockResolvedValue(status({ grants: [grant], restart_required: true }));
    render(<UsbTab name="web" running onChanged={() => {}} />);
    await screen.findByText(/kernel without USB support/i);
    // Offering an attach that cannot work is worse than not offering one.
    expect(screen.queryByRole("button", { name: /^attach$/i })).not.toBeInTheDocument();
  });

  it("restarts the sandbox from the warning", async () => {
    m.usbStatus.mockResolvedValue(status({ grants: [grant], restart_required: true }));
    render(<UsbTab name="web" running onChanged={() => {}} />);
    fireEvent.click(await screen.findByRole("button", { name: /^restart$/i }));
    await waitFor(() => expect(m.restart).toHaveBeenCalledWith("web"));
  });

  it("attaches a granted device", async () => {
    m.usbStatus.mockResolvedValue(status({ grants: [grant] }));
    render(<UsbTab name="web" running onChanged={() => {}} />);
    fireEvent.click(await screen.findByRole("button", { name: /^attach$/i }));
    await waitFor(() => expect(m.usbAttach).toHaveBeenCalledWith("web", "0403:6001"));
  });

  it("offers Detach, not Attach, for a device already attached", async () => {
    m.usbStatus.mockResolvedValue(status({ grants: [{ ...grant, attached: true }] }));
    render(<UsbTab name="web" running onChanged={() => {}} />);
    const detach = await screen.findByRole("button", { name: /^detach$/i });
    expect(screen.queryByRole("button", { name: /^attach$/i })).not.toBeInTheDocument();
    fireEvent.click(detach);
    await waitFor(() => expect(m.usbDetach).toHaveBeenCalledWith("web", "0403:6001"));
  });

  it("confirms before revoking, because revoke pulls a live device", async () => {
    m.usbStatus.mockResolvedValue(status({ grants: [{ ...grant, attached: true }] }));
    render(<UsbTab name="web" running onChanged={() => {}} />);
    fireEvent.click(await screen.findByRole("button", { name: /revoke 0403:6001/i }));
    expect(m.usbRevoke).not.toHaveBeenCalled();
    // The dialog's own Revoke button confirms.
    fireEvent.click(screen.getByRole("button", { name: /^revoke$/i }));
    await waitFor(() => expect(m.usbRevoke).toHaveBeenCalledWith("web", "0403:6001"));
  });

  it("does not offer attach on a stopped sandbox", async () => {
    m.usbStatus.mockResolvedValue(status({ grants: [grant] }));
    render(<UsbTab name="web" running={false} onChanged={() => {}} />);
    await screen.findByText("0403:6001");
    expect(screen.queryByRole("button", { name: /^attach$/i })).not.toBeInTheDocument();
  });

  it("does not offer to grant a device this sandbox already holds a grant for", async () => {
    m.usbStatus.mockResolvedValue(status({ grants: [grant] }));
    render(<UsbTab name="web" running onChanged={() => {}} />);
    await screen.findByText(/nothing else on the upstream/i);
    expect(screen.queryByRole("button", { name: /allow 0403:6001/i })).not.toBeInTheDocument();
  });

  it("shows an unshared device's bind command but no Allow button", async () => {
    m.usbListDevices.mockResolvedValue([
      {
        ...device,
        busid: "1-4",
        device: "10c4:ea60",
        shared: false,
        bind_command: "usbipd bind --busid 1-4",
      },
    ]);
    render(<UsbTab name="web" running onChanged={() => {}} />);
    await screen.findByText("usbipd bind --busid 1-4");
    expect(screen.queryByRole("button", { name: /allow 10c4:ea60/i })).not.toBeInTheDocument();
  });

  it("says which other sandbox is holding a device", async () => {
    m.usbListDevices.mockResolvedValue([{ ...device, attached_to: "api" }]);
    render(<UsbTab name="web" running onChanged={() => {}} />);
    await screen.findByText(/attached to api/i);
  });

  it("surfaces a failed attach instead of pretending it worked", async () => {
    m.usbStatus.mockResolvedValue(status({ grants: [grant] }));
    m.usbAttach.mockRejectedValue(new Error("the guest has no USB stack"));
    render(<UsbTab name="web" running onChanged={() => {}} />);
    fireEvent.click(await screen.findByRole("button", { name: /^attach$/i }));
    await screen.findByText(/no USB stack/i);
  });
});

/** DEEP-F3 — "No devices granted." is an INVENTORY of a host-only consent
 *  record (`SandboxConfig.usb`), and this tab is where an operator answers
 *  "what physical hardware can this sandbox reach?". With the daemon
 *  unreachable, or `usb_status` refused because the sandbox is busy under
 *  `lock_sandbox`, `status` stays `null` and the tab used to answer "none"
 *  beside its own error line. Nothing is written here (every write is
 *  per-row and there are no rows), but this project has already learned that
 *  a posture line gets read as an inventory. Not knowing is not the same as
 *  none. */
describe("UsbTab load state", () => {
  it("does not claim an empty grant inventory while the USB status is still loading", async () => {
    m.usbStatus.mockReturnValue(new Promise(() => {}));
    render(<UsbTab name="web" running onChanged={() => {}} />);
    await waitFor(() => expect(m.usbStatus).toHaveBeenCalled());
    expect(screen.queryByText(/no devices granted/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/nothing else on the upstream/i)).not.toBeInTheDocument();
    expect(screen.getByText(/has not read|could not read/i)).toBeInTheDocument();
    expect(m.usbAllow).not.toHaveBeenCalled();
    expect(m.usbRevoke).not.toHaveBeenCalled();
  });

  it("does not claim an empty grant inventory when the USB status could not be read", async () => {
    m.usbStatus.mockRejectedValue(new Error("sandbox 'web' is busy"));
    render(<UsbTab name="web" running onChanged={() => {}} />);
    await screen.findByText(/is busy/i);
    expect(screen.queryByText(/no devices granted/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/nothing else on the upstream/i)).not.toBeInTheDocument();
    expect(screen.getByText(/has not read|could not read/i)).toBeInTheDocument();
    expect(m.usbAllow).not.toHaveBeenCalled();
    expect(m.usbRevoke).not.toHaveBeenCalled();
  });

  it("still reports a genuinely read, genuinely empty grant inventory", async () => {
    m.usbStatus.mockResolvedValue(status());
    render(<UsbTab name="web" running onChanged={() => {}} />);
    expect(await screen.findByText(/no devices granted/i)).toBeInTheDocument();
  });
});
