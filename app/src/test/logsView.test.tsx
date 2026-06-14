import { render, screen, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { LogsView } from "../components/LogsView";

vi.mock("../lib/ipc", () => ({
  api: { readLogs: vi.fn() },
}));

describe("LogsView", () => {
  beforeEach(() => vi.clearAllMocks());

  it("fetches and renders console output", async () => {
    const { api } = await import("../lib/ipc");
    (api.readLogs as ReturnType<typeof vi.fn>).mockResolvedValue("hello from boot");
    render(<LogsView name="web" />);
    await waitFor(() => expect(api.readLogs).toHaveBeenCalledWith("web"));
    await screen.findByText(/hello from boot/);
  });

  it("surfaces a read error", async () => {
    const { api } = await import("../lib/ipc");
    (api.readLogs as ReturnType<typeof vi.fn>).mockRejectedValue(new Error("nope"));
    render(<LogsView name="web" />);
    await screen.findByText(/nope/);
  });
});
