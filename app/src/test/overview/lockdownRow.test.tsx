import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import type { LockdownView } from "../../lib/types";

const lockdown = vi.fn();
const unlock = vi.fn();
vi.mock("../../lib/ipc", () => ({ api: { lockdown: (n: string) => lockdown(n), unlock: (n: string) => unlock(n) } }));

import { LockdownRow } from "../../components/overview/LockdownRow";

const unlocked: LockdownView = { locked: false, account: null, net_blocked: false, restart_required: false, booted_as_account: false };
const locked: LockdownView = { locked: true, account: "izba-sb-web", net_blocked: true, restart_required: false, booted_as_account: true };

beforeEach(() => {
  lockdown.mockReset();
  unlock.mockReset();
});

describe("LockdownRow", () => {
  it("withholds the posture and its buttons when unknown", () => {
    render(<LockdownRow name="web" lockdown={{ ...locked, restart_required: true }} onChanged={() => {}} unknown />);
    expect(screen.getByText("unknown — refresh failed")).toBeInTheDocument();
    expect(screen.queryByRole("button")).toBeNull();
    expect(screen.queryByText(/restart to apply/i)).toBeNull();
    expect(screen.queryByText(/izba-sb-web/)).toBeNull();
  });

  it("offers Lock down when unlocked", () => {
    render(<LockdownRow name="web" lockdown={unlocked} onChanged={() => {}} />);
    expect(screen.getByText("unlocked")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /lock down/i })).toBeEnabled();
  });

  it("waits for approval, disables the button, then reports back", async () => {
    let resolve!: (v: "locked") => void;
    lockdown.mockReturnValue(new Promise((r) => (resolve = r)));
    const onChanged = vi.fn();
    render(<LockdownRow name="web" lockdown={unlocked} onChanged={onChanged} />);
    fireEvent.click(screen.getByRole("button", { name: /lock down/i }));
    expect(screen.getByText("Waiting for approval…")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /waiting for approval/i })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: /waiting for approval/i }));
    expect(lockdown).toHaveBeenCalledTimes(1);
    resolve("locked");
    await waitFor(() => expect(onChanged).toHaveBeenCalled());
  });

  it("treats a declined prompt as a quiet cancel, not an error", async () => {
    lockdown.mockResolvedValue("cancelled");
    render(<LockdownRow name="web" lockdown={unlocked} onChanged={() => {}} />);
    fireEvent.click(screen.getByRole("button", { name: /lock down/i }));
    expect(await screen.findByText("cancelled — nothing changed")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("shows a failure as an error", async () => {
    lockdown.mockRejectedValue("provision helper failed: boom");
    render(<LockdownRow name="web" lockdown={unlocked} onChanged={() => {}} />);
    fireEvent.click(screen.getByRole("button", { name: /lock down/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent("provision helper failed: boom");
  });

  it("summarizes the locked posture and confirms before unlocking", async () => {
    unlock.mockResolvedValue(undefined);
    const onChanged = vi.fn();
    render(<LockdownRow name="web" lockdown={locked} onChanged={onChanged} />);
    expect(screen.getByText("locked · izba-sb-web · network blocked")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /^unlock$/i }));
    expect(unlock).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: /^unlock sandbox$/i }));
    await waitFor(() => expect(unlock).toHaveBeenCalledWith("web"));
    await waitFor(() => expect(onChanged).toHaveBeenCalled());
  });

  it("renders network open when the firewall rule is absent", () => {
    render(<LockdownRow name="web" lockdown={{ ...locked, net_blocked: false }} onChanged={() => {}} />);
    expect(screen.getByText("locked · izba-sb-web · network open")).toBeInTheDocument();
  });

  it("badges a lock that has not taken effect yet", () => {
    render(<LockdownRow name="web" lockdown={{ ...locked, restart_required: true, booted_as_account: false }} onChanged={() => {}} />);
    expect(screen.getByText("restart to apply")).toBeInTheDocument();
  });

  it("badges an unlock that has not taken effect yet", () => {
    render(<LockdownRow name="web" lockdown={{ ...unlocked, restart_required: true, booted_as_account: true }} onChanged={() => {}} />);
    expect(screen.getByText("still running as account — restart to apply")).toBeInTheDocument();
  });

  it("drops a late result after the row unmounts (sandbox switched)", async () => {
    let resolve!: (v: "cancelled") => void;
    lockdown.mockReturnValue(new Promise((r) => (resolve = r)));
    const onChanged = vi.fn();
    const { unmount } = render(<LockdownRow name="web" lockdown={unlocked} onChanged={onChanged} />);
    fireEvent.click(screen.getByRole("button", { name: /lock down/i }));
    unmount();
    resolve("cancelled");
    await new Promise((r) => setTimeout(r, 0));
    expect(onChanged).not.toHaveBeenCalled();
  });

  it("drops a late success after unmount too", async () => {
    let resolve!: (v: "locked") => void;
    lockdown.mockReturnValue(new Promise((r) => (resolve = r)));
    const onChanged = vi.fn();
    const { unmount } = render(<LockdownRow name="web" lockdown={unlocked} onChanged={onChanged} />);
    fireEvent.click(screen.getByRole("button", { name: /lock down/i }));
    unmount();
    resolve("locked");
    await new Promise((r) => setTimeout(r, 0));
    expect(onChanged).not.toHaveBeenCalled();
  });
});
