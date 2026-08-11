import { render, screen, fireEvent, waitFor, act } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach, afterEach } from "vitest";
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
    // The #show_control_bar=1 fragment is load-bearing: without it the
    // KasmVNC client detects it is inside an iframe and enters Kasm
    // Workspaces' embedded mode (webp/resize/clipboard off, no initial
    // keyframe paint) — a black desktop with working input.
    expect(frame).toHaveAttribute("src", `${PROXY}#show_control_bar=1`);
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

  it("never lets the unmount stop overtake a still-resolving start", async () => {
    // The backend inserts the proxy into its registry only after a daemon
    // round-trip; a stop that lands before that insert removes nothing and
    // the late insert would orphan an unauthenticated listener. The cleanup
    // must therefore chain its stop behind the start's settlement.
    m.inspect.mockResolvedValue(live);
    let resolveStart!: (u: string) => void;
    m.vncProxyStart.mockReturnValue(new Promise<string>((r) => (resolveStart = r)));
    const { unmount } = render(<DisplayTab name="web" running onChanged={() => {}} />);
    await waitFor(() => expect(m.vncProxyStart).toHaveBeenCalledWith("web"));
    unmount();
    // Start still in flight: the stop must NOT have been issued yet.
    expect(m.vncProxyStop).not.toHaveBeenCalled();
    resolveStart(PROXY);
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

  it("blanks the tab until the sandbox it switched to has answered", async () => {
    // The previous sandbox's detail is still in state for that stretch, and it
    // carries that sandbox's password-bearing URL. It is not this tab's to offer.
    m.inspect.mockImplementation((n: string) =>
      n === "web" ? Promise.resolve(live) : new Promise<SandboxDetail>(() => {}),
    );
    const { rerender } = render(<DisplayTab name="web" running onChanged={() => {}} />);
    await screen.findByRole("button", { name: /open in browser/i });

    rerender(<DisplayTab name="api" running onChanged={() => {}} />);
    expect(screen.queryByRole("button", { name: /open in browser/i })).not.toBeInTheDocument();
    expect(screen.queryByTitle("Sandbox desktop")).not.toBeInTheDocument();
  });

  it("never paints a slow answer for the sandbox the tab already left", async () => {
    // "web" answers late; "api" answers at once. The late answer describes a
    // sandbox we are no longer looking at — painting it would put web's
    // password-bearing URL behind api's Open in browser button.
    const apiUrl = "http://izba:0th3rpw@127.0.0.1:6081/vnc.html";
    let answerWeb!: (d: SandboxDetail) => void;
    m.inspect.mockImplementation((n: string) =>
      n === "web"
        ? new Promise<SandboxDetail>((resolve) => {
            answerWeb = resolve;
          })
        : Promise.resolve(detail({ ...live, name: "api", vnc_url: apiUrl })),
    );

    const { rerender, container } = render(
      <DisplayTab name="web" running onChanged={() => {}} />,
    );
    rerender(<DisplayTab name="api" running onChanged={() => {}} />);
    await screen.findByTitle("Sandbox desktop");

    await act(async () => {
      answerWeb(deadDesktop);
    });

    expect(screen.queryByText(/not answering/i)).not.toBeInTheDocument();
    expect(container.innerHTML).not.toContain("s3cr3t");
    expect(container.innerHTML).not.toContain("0th3rpw");
    fireEvent.click(screen.getByRole("button", { name: /open in browser/i }));
    expect(openUrl).toHaveBeenCalledWith(apiUrl);
    expect(openUrl).not.toHaveBeenCalledWith(CREDENTIALED);
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

describe("DisplayTab polling", () => {
  // The tab is a live view of a desktop that takes seconds to boot, so it must
  // re-inspect on its own — a user who "waits for the desktop to come up" gets
  // nothing from a tab that only reads once.
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  /** Advance the poll clock and let the chained promises (inspect → proxy
   *  start) settle. */
  async function tickBy(ms: number) {
    await act(async () => {
      await vi.advanceTimersByTimeAsync(ms);
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
  }

  it("picks up a desktop that comes up — and one that goes away — without user action", async () => {
    m.inspect.mockResolvedValue(restartRequired);
    render(<DisplayTab name="web" running onChanged={() => {}} />);
    await tickBy(0);
    expect(screen.queryByTitle("Sandbox desktop")).not.toBeInTheDocument();

    // The desktop comes up between ticks.
    m.inspect.mockResolvedValue(live);
    await tickBy(3000);
    expect(screen.getByTitle("Sandbox desktop")).toHaveAttribute("src", `${PROXY}#show_control_bar=1`);

    // ...and dies again.
    m.inspect.mockResolvedValue(restartRequired);
    await tickBy(3000);
    expect(screen.queryByTitle("Sandbox desktop")).not.toBeInTheDocument();
  });

  it("stops polling once the tab unmounts", async () => {
    m.inspect.mockResolvedValue(notEnabled);
    const { unmount } = render(<DisplayTab name="web" running onChanged={() => {}} />);
    await tickBy(0);
    expect(m.inspect).toHaveBeenCalledTimes(1);
    await tickBy(3000);
    expect(m.inspect).toHaveBeenCalledTimes(2);

    unmount();
    await tickBy(30_000);
    // A tab nobody is looking at must not keep asking the daemon.
    expect(m.inspect).toHaveBeenCalledTimes(2);
  });

  it("skips a tick while the previous inspect is still in flight", async () => {
    let answer!: (d: SandboxDetail) => void;
    m.inspect.mockImplementation(
      () =>
        new Promise<SandboxDetail>((resolve) => {
          answer = resolve;
        }),
    );
    render(<DisplayTab name="web" running onChanged={() => {}} />);
    await tickBy(0);
    expect(m.inspect).toHaveBeenCalledTimes(1);

    // Several intervals elapse against a hung daemon: the overlap guard must
    // not stack requests behind it.
    await tickBy(12_000);
    expect(m.inspect).toHaveBeenCalledTimes(1);

    answer(notEnabled);
    await tickBy(0);
    await tickBy(3000);
    expect(m.inspect).toHaveBeenCalledTimes(2);
  });
});
