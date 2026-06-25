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
    fireEvent.click(screen.getByRole("switch", { name: /Enforce firewall after adding/i }));
    fireEvent.click(screen.getByRole("button", { name: /Add .* selected/ }));
    await waitFor(() => expect(add).toHaveBeenCalledWith("web", expect.anything(), true));
  });

  it("git delta exclusion: covered repo excluded, uncovered repo listed", async () => {
    const add = api.policyAddEndpoints as Mock;
    const rows = [
      // Covered by policy.git — should be excluded from candidates
      sum({
        host: "github.com",
        last_method: "POST",
        last_path: "/o/a/git-upload-pack",
      }),
      // Not covered by policy.git — should appear in candidates
      sum({
        host: "github.com",
        last_method: "POST",
        last_path: "/o/b/git-upload-pack",
      }),
    ];
    render(
      <SeedDialog
        name="web"
        rows={rows}
        enforcing={false}
        policy={{ enforcing: false, allow: [], git: [{ repo: "github.com/o/a", access: "read" }] }}
        onClose={() => {}}
        onApplied={() => {}}
      />
    );
    // Covered repo must not appear
    expect(screen.queryByText(/github\.com\/o\/a/)).toBeNull();
    // Uncovered repo must appear
    expect(screen.getByText(/github\.com\/o\/b/)).toBeInTheDocument();
    // Add the uncovered one
    fireEvent.click(screen.getByRole("button", { name: /Add .* selected/ }));
    await waitFor(() =>
      expect(add).toHaveBeenCalledWith(
        "web",
        [{ kind: "git", target: "github.com/o/b", access: "read" }],
        false
      )
    );
  });

  it("raw-IP row is rendered but disabled and excluded from policyAddEndpoints", async () => {
    const add = api.policyAddEndpoints as Mock;
    const rows = [
      // Raw IP row: host === null
      sum({ host: null, dest_ip: "10.0.0.1", port: 80, last_method: null, last_path: null }),
      // Regular HTTP row that is selectable
      sum({ host: "pypi.org", port: 443, last_method: "GET", last_path: "/" }),
    ];
    render(
      <SeedDialog
        name="web"
        rows={rows}
        enforcing={false}
        policy={{ enforcing: false, allow: [], git: [] }}
        onClose={() => {}}
        onApplied={() => {}}
      />
    );
    // Raw IP row must be visible (shows dest_ip:port)
    expect(screen.getByText("10.0.0.1:80")).toBeInTheDocument();
    // Its checkbox must be disabled
    const checkboxes = screen.getAllByRole("checkbox");
    // The checkbox for the raw-IP row is disabled
    const rawIpCheckbox = checkboxes.find((cb) => (cb as HTMLInputElement).disabled && cb.closest("label")?.textContent?.includes("10.0.0.1"));
    expect(rawIpCheckbox).toBeDefined();
    expect(rawIpCheckbox).toBeDisabled();
    // Clicking Add should only include pypi.org, not the raw IP
    fireEvent.click(screen.getByRole("button", { name: /Add .* selected/ }));
    await waitFor(() =>
      expect(add).toHaveBeenCalledWith(
        "web",
        [{ kind: "http", host: "pypi.org", port: 443, access: "read" }],
        false
      )
    );
  });

  it("surfaces an error and stays open when the apply fails", async () => {
    (api.policyAddEndpoints as Mock).mockRejectedValue(new Error("daemon offline"));
    const onApplied = vi.fn();
    const onClose = vi.fn();
    render(
      <SeedDialog
        name="web"
        rows={[sum({ host: "pypi.org", port: 443, last_method: "GET", last_path: "/simple/" })]}
        policy={{ enforcing: false, allow: [], git: [] }}
        enforcing={false}
        onClose={onClose}
        onApplied={onApplied}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: /Add .* selected/ }));
    // The error is surfaced and the dialog is NOT dismissed (no silent drop).
    expect(await screen.findByRole("alert")).toHaveTextContent(/daemon offline/);
    expect(onApplied).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();
  });
});
