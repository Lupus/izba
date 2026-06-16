import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach } from "vitest";
import { PolicyEditor } from "../components/PolicyEditor";
import { api } from "../lib/ipc";

vi.mock("../lib/ipc", () => ({
  api: { policyShow: vi.fn(), policySet: vi.fn() },
}));

beforeEach(() => {
  vi.clearAllMocks();
  (api.policyShow as ReturnType<typeof vi.fn>).mockResolvedValue({
    enforcing: true,
    allow: ["api.x.com", { host: "db.internal", ports: [5432] }],
  });
});

describe("PolicyEditor", () => {
  it("renders entries and saves normalized rows", async () => {
    render(<PolicyEditor name="web" />);
    await screen.findByDisplayValue("api.x.com");
    fireEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() =>
      expect(api.policySet).toHaveBeenCalledWith("web", [
        { host: "api.x.com", ports: [80, 443] },
        { host: "db.internal", ports: [5432] },
      ]),
    );
  });

  it("adds a port to a host via the add-port field", async () => {
    render(<PolicyEditor name="web" />);
    await screen.findByDisplayValue("db.internal");
    // Second row (db.internal) has the second "add port" input.
    const adders = screen.getAllByLabelText("add port");
    fireEvent.change(adders[1], { target: { value: "8443" } });
    fireEvent.keyDown(adders[1], { key: "Enter" });
    fireEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() =>
      expect(api.policySet).toHaveBeenCalledWith("web", [
        { host: "api.x.com", ports: [80, 443] },
        { host: "db.internal", ports: [5432, 8443] },
      ]),
    );
  });

  it("removes a port chip", async () => {
    render(<PolicyEditor name="web" />);
    await screen.findByDisplayValue("api.x.com");
    fireEvent.click(screen.getByRole("button", { name: /remove port 80/i }));
    fireEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() =>
      expect(api.policySet).toHaveBeenCalledWith("web", [
        { host: "api.x.com", ports: [443] },
        { host: "db.internal", ports: [5432] },
      ]),
    );
  });
});
