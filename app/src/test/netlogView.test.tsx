import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach } from "vitest";
import { NetlogView } from "../components/NetlogView";
import { api } from "../lib/ipc";
import type { PolicyView } from "../lib/types";

vi.mock("../lib/ipc", () => ({
  api: {
    readNetlog: vi.fn(),
    policyShow: vi.fn(),
    policyAllow: vi.fn(),
    policyBlock: vi.fn(),
    policyEnable: vi.fn(),
  },
}));

const allowedNamed = {
  host: "api.x.com", dest_ip: "1.1.1.1", port: 443, tier: "l7", verdict: "allow",
  allow_count: 3, deny_count: 0, first_seen_ms: 1, last_seen_ms: 9,
  last_method: "GET", last_path: "/v1",
};
const deniedRawIp = {
  host: null, dest_ip: "9.9.9.9", port: 22, tier: "l3", verdict: "deny",
  allow_count: 0, deny_count: 2, first_seen_ms: 1, last_seen_ms: 5,
  last_method: null, last_path: null,
};

function mockPolicy(p: PolicyView) {
  (api.policyShow as ReturnType<typeof vi.fn>).mockResolvedValue(p);
}

beforeEach(() => {
  vi.clearAllMocks();
  mockPolicy({ enforcing: true, allow: [] });
  (api.readNetlog as ReturnType<typeof vi.fn>).mockResolvedValue([allowedNamed, deniedRawIp]);
});

describe("NetlogView", () => {
  it("offers Block on a host the policy already allows", async () => {
    mockPolicy({ enforcing: true, allow: ["api.x.com"] }); // bare host ⇒ 80, 443
    render(<NetlogView name="web" />);
    fireEvent.click(await screen.findByRole("button", { name: /block api\.x\.com/i }));
    await waitFor(() => expect(api.policyBlock).toHaveBeenCalledWith("web", "api.x.com", 443));
  });

  it("offers Allow on a host the policy does not yet permit", async () => {
    render(<NetlogView name="web" />); // allow: [] from beforeEach
    fireEvent.click(await screen.findByRole("button", { name: /allow api\.x\.com/i }));
    await waitFor(() => expect(api.policyAllow).toHaveBeenCalledWith("web", "api.x.com", 443));
  });

  it("flips the row to allowed right after clicking Allow", async () => {
    // Policy starts empty; clicking Allow adds the host, and the immediate
    // refresh re-reads policy so the row reflects the new state without waiting.
    let allow: PolicyView["allow"] = [];
    (api.policyShow as ReturnType<typeof vi.fn>).mockImplementation(async () => ({
      enforcing: true,
      allow,
    }));
    (api.policyAllow as ReturnType<typeof vi.fn>).mockImplementation(async () => {
      allow = ["api.x.com"];
    });
    render(<NetlogView name="web" />);
    fireEvent.click(await screen.findByRole("button", { name: /allow api\.x\.com/i }));
    // After the action+refresh the button toggles to Block (state visibly changed).
    await screen.findByRole("button", { name: /block api\.x\.com/i });
  });

  it("disables Allow on a raw-IP row", async () => {
    render(<NetlogView name="web" />);
    await screen.findByText(/9\.9\.9\.9/);
    expect(screen.getByRole("button", { name: /allow 9\.9\.9\.9/i })).toBeDisabled();
  });

  it("shows the enable-firewall banner for a bare sandbox", async () => {
    mockPolicy({ enforcing: false, allow: [] });
    render(<NetlogView name="web" />);
    const btn = await screen.findByRole("button", { name: /enable firewall/i });
    fireEvent.click(btn);
    await waitFor(() => expect(api.policyEnable).toHaveBeenCalledWith("web"));
  });
});
