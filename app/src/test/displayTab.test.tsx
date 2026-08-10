import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach } from "vitest";
import type { SandboxDetail } from "../lib/types";

// ── hoisted mocks ────────────────────────────────────────────────────────────

const m = vi.hoisted(() => ({
  inspect: vi.fn(),
  vncSet: vi.fn(),
  vncProxyStart: vi.fn(),
  vncProxyStop: vi.fn(),
  restart: vi.fn(),
  start: vi.fn(),
}));

vi.mock("../lib/ipc", () => ({ api: m }));

const { openUrl } = vi.hoisted(() => ({ openUrl: vi.fn() }));
vi.mock("@tauri-apps/plugin-opener", () => ({ openUrl }));

import { DisplayTab } from "../components/DisplayTab";

// ── fixtures ─────────────────────────────────────────────────────────────────

/** The credentialed URL. Its password must never reach the DOM. */
const CREDENTIALED = "http://izba:s3cr3t@127.0.0.1:6080/vnc.html?autoconnect=1";
const PROXY = "http://127.0.0.1:9999/";

const detail = (over: Partial<SandboxDetail> = {}): SandboxDetail => ({
  name: "web",
  image: "ubuntu:24.04",
  status: "running",
  workspace: "/home/u/proj",
  ports: [],
  volumes: [],
  container: "running",
  docker: false,
  cpus: 2,
  mem_mb: 2048,
  confinement: "seccomp+landlock",
  vnc: false,
  vnc_running: false,
  vnc_url: null,
  vnc_restart_required: false,
  ...over,
});

const notEnabled = detail();
const notRunning = detail({ vnc: true, status: "stopped" });
const restartRequired = detail({ vnc: true, status: "running", vnc_restart_required: true });
const live = detail({ vnc: true, vnc_running: true, vnc_url: CREDENTIALED });
const deadDesktop = detail({ vnc: true, vnc_running: false, vnc_url: CREDENTIALED });
const liveOff = detail({ vnc: false, vnc_running: true, vnc_url: CREDENTIALED });

beforeEach(() => {
  vi.clearAllMocks();
  m.inspect.mockResolvedValue(notEnabled);
  m.vncProxyStart.mockResolvedValue(PROXY);
  for (const f of [m.vncSet, m.vncProxyStop, m.restart, m.start]) f.mockResolvedValue(undefined);
  openUrl.mockResolvedValue(undefined);
  Object.assign(navigator, { clipboard: { writeText: vi.fn().mockResolvedValue(undefined) } });
});

// ── tests ────────────────────────────────────────────────────────────────────

describe("DisplayTab", () => {
  it("offers to enable the desktop when it is off, and re-reads the sandbox after", async () => {
    render(<DisplayTab name="web" running onChanged={() => {}} />);
    fireEvent.click(await screen.findByRole("button", { name: /enable desktop/i }));
    await waitFor(() => expect(m.vncSet).toHaveBeenCalledWith("web", true));
    // The tab mirrors the daemon, so it must re-inspect rather than guess.
    await waitFor(() => expect(m.inspect).toHaveBeenCalledTimes(2));
    // Nothing is proxied while there is no live desktop.
    expect(m.vncProxyStart).not.toHaveBeenCalled();
  });

  it("says the sandbox is stopped and offers to start it", async () => {
    m.inspect.mockResolvedValue(notRunning);
    render(<DisplayTab name="web" running={false} onChanged={() => {}} />);
    await screen.findByText(/stopped/i);
    fireEvent.click(screen.getByRole("button", { name: /^start$/i }));
    await waitFor(() => expect(m.start).toHaveBeenCalledWith("web"));
  });

  it("asks for a restart when the booted display config is stale", async () => {
    m.inspect.mockResolvedValue(restartRequired);
    render(<DisplayTab name="web" running onChanged={() => {}} />);
    await screen.findByText(/restart the sandbox to apply the desktop change/i);
    fireEvent.click(screen.getByRole("button", { name: /^restart$/i }));
    await waitFor(() => expect(m.restart).toHaveBeenCalledWith("web"));
  });

  it("embeds the credential-less proxy URL and never puts the password in the DOM", async () => {
    m.inspect.mockResolvedValue(live);
    const { container } = render(<DisplayTab name="web" running onChanged={() => {}} />);
    const frame = await screen.findByTitle("Sandbox desktop");
    expect(frame).toHaveAttribute("src", PROXY);
    await waitFor(() => expect(m.vncProxyStart).toHaveBeenCalledWith("web"));
    expect(container.innerHTML).not.toContain("s3cr3t");
    expect(container.innerHTML).not.toContain(CREDENTIALED);
  });

  it("stops the proxy when the tab goes away", async () => {
    m.inspect.mockResolvedValue(live);
    const { unmount } = render(<DisplayTab name="web" running onChanged={() => {}} />);
    await screen.findByTitle("Sandbox desktop");
    unmount();
    await waitFor(() => expect(m.vncProxyStop).toHaveBeenCalledWith("web"));
  });

  it("stops the old sandbox's proxy when the tab switches sandbox", async () => {
    m.inspect.mockResolvedValue(live);
    const { rerender } = render(<DisplayTab name="web" running onChanged={() => {}} />);
    await screen.findByTitle("Sandbox desktop");
    m.inspect.mockResolvedValue({ ...live, name: "api" });
    rerender(<DisplayTab name="api" running onChanged={() => {}} />);
    // The stop must name the sandbox we are leaving, not the one we arrive at.
    await waitFor(() => expect(m.vncProxyStop).toHaveBeenCalledWith("web"));
    await waitFor(() => expect(m.vncProxyStart).toHaveBeenCalledWith("api"));
    expect(m.vncProxyStop).not.toHaveBeenCalledWith("api");
  });

  it("keeps embedding while asking for a restart the running desktop still needs", async () => {
    m.inspect.mockResolvedValue(detail({ ...live, vnc_restart_required: true }));
    render(<DisplayTab name="web" running onChanged={() => {}} />);
    // Both truths at once: this desktop works, and it is not the configured one.
    await screen.findByText(/restart the sandbox to apply the desktop change/i);
    expect(await screen.findByTitle("Sandbox desktop")).toBeInTheDocument();
  });

  it("starts the new sandbox's proxy even when stopping the old one fails", async () => {
    m.inspect.mockResolvedValue(live);
    m.vncProxyStop.mockRejectedValue(new Error("state poisoned"));
    const { rerender } = render(<DisplayTab name="web" running onChanged={() => {}} />);
    await screen.findByTitle("Sandbox desktop");
    m.inspect.mockResolvedValue({ ...live, name: "api" });
    rerender(<DisplayTab name="api" running onChanged={() => {}} />);
    await waitFor(() => expect(m.vncProxyStart).toHaveBeenCalledWith("api"));
  });

  it("opens and copies the credentialed URL without showing it", async () => {
    m.inspect.mockResolvedValue(live);
    render(<DisplayTab name="web" running onChanged={() => {}} />);
    fireEvent.click(await screen.findByRole("button", { name: /open in browser/i }));
    await waitFor(() => expect(openUrl).toHaveBeenCalledWith(CREDENTIALED));
    fireEvent.click(screen.getByRole("button", { name: /copy url/i }));
    await waitFor(() =>
      expect(navigator.clipboard.writeText).toHaveBeenCalledWith(CREDENTIALED),
    );
  });

  it("warns, with the guest log command, when the desktop is not answering", async () => {
    m.inspect.mockResolvedValue(deadDesktop);
    render(<DisplayTab name="web" running onChanged={() => {}} />);
    await screen.findByText(/\/var\/log\/izba-vnc\.log/);
  });

  it("warns when a live desktop is disabled in config, and offers to re-enable it", async () => {
    m.inspect.mockResolvedValue(liveOff);
    render(<DisplayTab name="web" running onChanged={() => {}} />);
    await screen.findByText(/disabled in config/i);
    fireEvent.click(screen.getByRole("button", { name: /enable desktop/i }));
    await waitFor(() => expect(m.vncSet).toHaveBeenCalledWith("web", true));
  });

  it("keeps open-in-browser working when the embed proxy fails to start", async () => {
    m.inspect.mockResolvedValue(live);
    m.vncProxyStart.mockRejectedValue(new Error("port bind refused"));
    render(<DisplayTab name="web" running onChanged={() => {}} />);
    await screen.findByText(/port bind refused/i);
    expect(screen.queryByTitle("Sandbox desktop")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /open in browser/i }));
    await waitFor(() => expect(openUrl).toHaveBeenCalledWith(CREDENTIALED));
  });

  it("says so when the clipboard refuses instead of failing silently", async () => {
    m.inspect.mockResolvedValue(live);
    Object.assign(navigator, {
      clipboard: { writeText: vi.fn().mockRejectedValue(new Error("denied")) },
    });
    render(<DisplayTab name="web" running onChanged={() => {}} />);
    fireEvent.click(await screen.findByRole("button", { name: /copy url/i }));
    // The URL is a secret: the fallback can only point at the other button.
    await screen.findByText(/use open in browser instead/i);
  });

  it("shows why the sandbox could not be read at all", async () => {
    m.inspect.mockRejectedValue(new Error("no such sandbox"));
    render(<DisplayTab name="web" running onChanged={() => {}} />);
    await screen.findByText(/no such sandbox/i);
  });

  it("surfaces a failed disable instead of pretending it worked", async () => {
    m.inspect.mockResolvedValue(live);
    m.vncSet.mockRejectedValue(new Error("daemon says no"));
    render(<DisplayTab name="web" running onChanged={() => {}} />);
    fireEvent.click(await screen.findByRole("button", { name: /disable desktop/i }));
    await screen.findByText(/daemon says no/i);
  });
});
