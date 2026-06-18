import { render, screen } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach } from "vitest";
import { FirewallStatus } from "../components/FirewallStatus";
import { api } from "../lib/ipc";

vi.mock("../lib/ipc", () => ({
  api: { policyShow: vi.fn() },
}));

beforeEach(() => vi.clearAllMocks());

describe("FirewallStatus", () => {
  it("shows the bare-sandbox state when not enforcing", async () => {
    (api.policyShow as ReturnType<typeof vi.fn>).mockResolvedValue({ enforcing: false, allow: [], git: [] });
    render(<FirewallStatus name="web" />);
    expect(await screen.findByText(/bare sandbox/i)).toBeInTheDocument();
  });

  it("shows the enforcing state with a pluralized rule count", async () => {
    (api.policyShow as ReturnType<typeof vi.fn>).mockResolvedValue({
      enforcing: true,
      allow: ["api.x.com", { host: "db.internal", ports: [5432] }],
      git: [],
    });
    render(<FirewallStatus name="web" />);
    expect(await screen.findByText(/firewall enforcing · 2 allow rules/i)).toBeInTheDocument();
  });

  it("renders nothing if the policy cannot be read", async () => {
    (api.policyShow as ReturnType<typeof vi.fn>).mockRejectedValue(new Error("no daemon"));
    const { container } = render(<FirewallStatus name="web" />);
    // Effect runs as a microtask; flush it.
    await Promise.resolve();
    expect(container).toBeEmptyDOMElement();
  });
});
