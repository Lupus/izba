import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach } from "vitest";
import type { Mock } from "vitest";
import { SeedDialog } from "../components/SeedDialog";
import { api } from "../lib/ipc";
import type { EndpointSummary } from "../lib/types";

vi.mock("../lib/ipc", () => ({
  api: {
    policyAddEndpoints: vi.fn(),
  },
}));

/** Minimal EndpointSummary factory — only supply what differs per test. */
function sum(overrides: Partial<EndpointSummary>): EndpointSummary {
  return {
    host: "example.com",
    dest_ip: "1.2.3.4",
    port: 443,
    tier: "l7",
    verdict: "allow",
    allow_count: 1,
    deny_count: 0,
    first_seen_ms: 1,
    last_seen_ms: 9,
    last_method: "GET",
    last_path: "/",
    ...overrides,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  (api.policyAddEndpoints as Mock).mockResolvedValue(undefined);
});

describe("SeedDialog", () => {
  it("lists only the delta and adds selected via policyAddEndpoints", async () => {
    const add = api.policyAddEndpoints as Mock;
    const rows = [
      sum({ host: "pypi.org", port: 443, last_method: "GET", last_path: "/simple/" }),
      sum({ host: "api.x.com", port: 443, last_method: "POST", last_path: "/v1" }), // already in policy
    ];
    render(<SeedDialog name="web" rows={rows} enforcing={false}
      policy={{ enforcing:false, allow:[{host:"api.x.com",ports:[443]}], git:[] }}
      onClose={()=>{}} onApplied={()=>{}} />);
    expect(screen.queryByText(/api\.x\.com/)).toBeNull();          // covered → excluded
    expect(screen.getByText(/pypi\.org/)).toBeInTheDocument();      // delta
    fireEvent.click(screen.getByRole("button", { name: /Add .* selected/ }));
    await waitFor(() => expect(add).toHaveBeenCalledWith("web",
      [{ kind: "http", host: "pypi.org", port: 443, access: "read" }], false));
  });

  it("enforce-after checkbox is prominent when firewall is off and passes enforce=true when checked", async () => {
    const add = api.policyAddEndpoints as Mock;
    render(<SeedDialog name="web" rows={[sum({host:"pypi.org",port:443,last_method:"GET",last_path:"/"})]}
      enforcing={false} policy={{enforcing:false,allow:[],git:[]}} onClose={()=>{}} onApplied={()=>{}} />);
    expect(screen.getByText(/firewall is currently OFF/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("checkbox", { name: /Enforce firewall after adding/i }));
    fireEvent.click(screen.getByRole("button", { name: /Add .* selected/ }));
    await waitFor(() => expect(add).toHaveBeenCalledWith("web", expect.anything(), true));
  });
});
