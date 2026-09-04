import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach } from "vitest";
import type { Mock } from "vitest";
import { SeedDialog, buildCandidates } from "../components/SeedDialog";
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

const bare = { enforcing: false, allow: [], git: [] };

/** The dialog's candidate rows, top to bottom, as their accessible names. */
function listedLabels(): string[] {
  return screen
    .getAllByRole("checkbox")
    .map((cb) => cb.getAttribute("aria-label") ?? "");
}

function addButton(): HTMLElement {
  return screen.getByRole("button", { name: /^Add \d+ selected to allow-list$/ });
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
    fireEvent.click(screen.getByRole("checkbox", { name: "pypi.org:443" }));
    fireEvent.click(addButton());
    await waitFor(() => expect(add).toHaveBeenCalledWith("web",
      [{ kind: "http", host: "pypi.org", port: 443, access: "read" }], false));
  });

  it("enforce-after checkbox is prominent when firewall is off and passes enforce=true when checked", async () => {
    const add = api.policyAddEndpoints as Mock;
    render(<SeedDialog name="web" rows={[sum({host:"pypi.org",port:443,last_method:"GET",last_path:"/"})]}
      enforcing={false} policy={bare} onClose={()=>{}} onApplied={()=>{}} />);
    expect(screen.getByText(/firewall is currently OFF/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("switch", { name: /Enforce firewall after adding/i }));
    fireEvent.click(screen.getByRole("button", { name: "Select all" }));
    fireEvent.click(addButton());
    await waitFor(() => expect(add).toHaveBeenCalledWith("web", expect.anything(), true));
  });

  it("git delta exclusion: covered repo excluded, uncovered repo listed", async () => {
    const add = api.policyAddEndpoints as Mock;
    const rows = [
      // Covered by policy.git — should be excluded from candidates
      sum({ host: "github.com", last_method: "POST", last_path: "/o/a/git-upload-pack" }),
      // Not covered by policy.git — should appear in candidates
      sum({ host: "github.com", last_method: "POST", last_path: "/o/b/git-upload-pack" }),
    ];
    render(
      <SeedDialog name="web" rows={rows} enforcing={false}
        policy={{ enforcing: false, allow: [], git: [{ repo: "github.com/o/a", access: "read" }] }}
        onClose={() => {}} onApplied={() => {}} />
    );
    expect(screen.queryByText(/github\.com\/o\/a/)).toBeNull();
    expect(screen.getByText(/github\.com\/o\/b/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Select all" }));
    fireEvent.click(addButton());
    await waitFor(() =>
      expect(add).toHaveBeenCalledWith("web", [{ kind: "git", target: "github.com/o/b", access: "read" }], false)
    );
  });

  it("raw-IP row is rendered but disabled and excluded from policyAddEndpoints, even under Select all", async () => {
    const add = api.policyAddEndpoints as Mock;
    const rows = [
      sum({ host: null, dest_ip: "10.0.0.1", port: 80, last_method: null, last_path: null }),
      sum({ host: "pypi.org", port: 443, last_method: "GET", last_path: "/" }),
    ];
    render(<SeedDialog name="web" rows={rows} enforcing={false} policy={bare}
      onClose={() => {}} onApplied={() => {}} />);
    expect(screen.getByText("10.0.0.1:80")).toBeInTheDocument();
    const rawIpCheckbox = screen.getByRole("checkbox", { name: "10.0.0.1:80" });
    expect(rawIpCheckbox).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Select all" }));
    expect(rawIpCheckbox).not.toBeChecked();
    expect(addButton()).toHaveTextContent("Add 1 selected to allow-list");
    fireEvent.click(addButton());
    await waitFor(() =>
      expect(add).toHaveBeenCalledWith("web", [{ kind: "http", host: "pypi.org", port: 443, access: "read" }], false)
    );
  });

  it("surfaces an error and stays open when the apply fails", async () => {
    (api.policyAddEndpoints as Mock).mockRejectedValue(new Error("daemon offline"));
    const onApplied = vi.fn();
    const onClose = vi.fn();
    render(
      <SeedDialog name="web" rows={[sum({ host: "pypi.org", port: 443, last_method: "GET", last_path: "/simple/" })]}
        policy={bare} enforcing={false} onClose={onClose} onApplied={onApplied} />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Select all" }));
    fireEvent.click(addButton());
    expect(await screen.findByRole("alert")).toHaveTextContent(/daemon offline/);
    expect(onApplied).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();
  });
});

describe("SeedDialog selection (a consent surface: nothing is approved by default)", () => {
  const rows = [
    sum({ host: "pypi.org", port: 443 }),
    sum({ host: "npmjs.org", port: 443 }),
    sum({ host: null, dest_ip: "10.0.0.1", port: 80, last_method: null, last_path: null }),
  ];

  it("opens with no candidate selected and the submit action disabled at 0", () => {
    render(<SeedDialog name="web" rows={rows} enforcing={true} policy={{ ...bare, enforcing: true }}
      onClose={() => {}} onApplied={() => {}} />);
    for (const cb of screen.getAllByRole("checkbox")) expect(cb).not.toBeChecked();
    expect(addButton()).toBeDisabled();
    expect(addButton()).toHaveTextContent("Add 0 selected to allow-list");
  });

  it("Select all / Deselect all act on every selectable candidate and the count follows", () => {
    render(<SeedDialog name="web" rows={rows} enforcing={true} policy={{ ...bare, enforcing: true }}
      onClose={() => {}} onApplied={() => {}} />);
    fireEvent.click(screen.getByRole("button", { name: "Select all" }));
    expect(screen.getByRole("checkbox", { name: "pypi.org:443" })).toBeChecked();
    expect(screen.getByRole("checkbox", { name: "npmjs.org:443" })).toBeChecked();
    expect(screen.getByRole("checkbox", { name: "10.0.0.1:80" })).not.toBeChecked();
    expect(addButton()).toBeEnabled();
    expect(addButton()).toHaveTextContent("Add 2 selected to allow-list");
    fireEvent.click(screen.getByRole("button", { name: "Deselect all" }));
    for (const cb of screen.getAllByRole("checkbox")) expect(cb).not.toBeChecked();
    expect(addButton()).toBeDisabled();
    expect(addButton()).toHaveTextContent("Add 0 selected to allow-list");
  });

  it("a single checkbox toggles its own row only and the count follows", () => {
    render(<SeedDialog name="web" rows={rows} enforcing={true} policy={{ ...bare, enforcing: true }}
      onClose={() => {}} onApplied={() => {}} />);
    fireEvent.click(screen.getByRole("checkbox", { name: "npmjs.org:443" }));
    expect(screen.getByRole("checkbox", { name: "npmjs.org:443" })).toBeChecked();
    expect(screen.getByRole("checkbox", { name: "pypi.org:443" })).not.toBeChecked();
    expect(addButton()).toHaveTextContent("Add 1 selected to allow-list");
    fireEvent.click(screen.getByRole("checkbox", { name: "npmjs.org:443" }));
    expect(addButton()).toHaveTextContent("Add 0 selected to allow-list");
  });

  it("every control is a real button or checkbox (keyboard-reachable, nothing hover-only)", () => {
    render(<SeedDialog name="web" rows={rows} enforcing={true} policy={{ ...bare, enforcing: true }}
      onClose={() => {}} onApplied={() => {}} />);
    expect(screen.getByRole("button", { name: "Select all" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Deselect all" })).toBeInTheDocument();
    expect(screen.getAllByRole("checkbox")).toHaveLength(3);
  });

  it("renders candidate rows in buildCandidates' key order", () => {
    const raw = sum({ host: null, dest_ip: "10.0.0.1", port: 80, last_method: null, last_path: null });
    const pypi = sum({ host: "pypi.org", port: 443 });
    const gitRow = sum({ host: "github.com", last_method: "POST", last_path: "/o/b/git-upload-pack" });
    const npm = sum({ host: "npmjs.org", port: 443 });
    render(<SeedDialog name="web" rows={[raw, pypi, gitRow, npm]} enforcing={true}
      policy={{ ...bare, enforcing: true }} onClose={() => {}} onApplied={() => {}} />);
    expect(listedLabels()).toEqual([
      "git clone → github.com/o/b",
      "npmjs.org:443",
      "pypi.org:443",
      "10.0.0.1:80",
    ]);
  });
});

describe("SeedDialog snapshot (a review is a frozen list, not a live feed)", () => {
  const pypi = sum({ host: "pypi.org", port: 443 });
  const npm = sum({ host: "npmjs.org", port: 443 });
  const dialog = (rows: EndpointSummary[]) => (
    <SeedDialog name="web" rows={rows} enforcing={true} policy={{ ...bare, enforcing: true }}
      onClose={() => {}} onApplied={() => {}} />
  );

  it("keeps the list and its order frozen while the rows prop changes underneath", () => {
    const { rerender } = render(dialog([pypi]));
    expect(listedLabels()).toEqual(["pypi.org:443"]);
    rerender(dialog([npm, pypi]));
    expect(listedLabels()).toEqual(["pypi.org:443"]);
    expect(screen.queryByText("npmjs.org:443")).toBeNull();
  });

  it("reports new endpoints as a non-blocking notice, distinct from the reviewed set", () => {
    const { rerender } = render(dialog([pypi]));
    expect(screen.getByRole("status")).toBeEmptyDOMElement();
    rerender(dialog([npm, pypi]));
    expect(screen.getByRole("status")).toHaveTextContent(
      "1 new endpoint(s) observed since this review — refresh to include them.",
    );
    // The submit action is untouched by the notice.
    fireEvent.click(screen.getByRole("checkbox", { name: "pypi.org:443" }));
    expect(addButton()).toBeEnabled();
  });

  it("Refresh folds new traffic in, keeps the user's existing ticks, leaves new rows unselected", () => {
    const { rerender } = render(dialog([pypi]));
    fireEvent.click(screen.getByRole("checkbox", { name: "pypi.org:443" }));
    rerender(dialog([npm, pypi]));
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
    expect(listedLabels()).toEqual(["npmjs.org:443", "pypi.org:443"]);
    expect(screen.getByRole("checkbox", { name: "pypi.org:443" })).toBeChecked();
    expect(screen.getByRole("checkbox", { name: "npmjs.org:443" })).not.toBeChecked();
    expect(addButton()).toHaveTextContent("Add 1 selected to allow-list");
    expect(screen.getByRole("status")).toBeEmptyDOMElement();
  });

  it("a reshuffle of the same membership leaves the frozen list untouched and raises no notice", () => {
    const { rerender } = render(dialog([npm, pypi]));
    expect(listedLabels()).toEqual(["npmjs.org:443", "pypi.org:443"]);
    rerender(dialog([pypi, npm]));
    expect(listedLabels()).toEqual(["npmjs.org:443", "pypi.org:443"]);
    expect(screen.getByRole("status")).toBeEmptyDOMElement();
  });

  it("Refresh is available even when the snapshot was empty at open", () => {
    const { rerender } = render(dialog([]));
    expect(screen.getByText(/No new endpoints in this review/)).toBeInTheDocument();
    rerender(dialog([pypi]));
    expect(screen.getByRole("status")).toHaveTextContent(/1 new endpoint/);
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
    expect(listedLabels()).toEqual(["pypi.org:443"]);
  });

  it("Refresh prunes a departed candidate from checked, and it comes back unticked (not resurrected) if it returns", async () => {
    const add = api.policyAddEndpoints as Mock;
    const { rerender } = render(dialog([pypi, npm]));
    fireEvent.click(screen.getByRole("checkbox", { name: "pypi.org:443" }));
    fireEvent.click(screen.getByRole("checkbox", { name: "npmjs.org:443" }));

    // npm drops out of live (e.g. it became covered by policy out of band).
    rerender(dialog([pypi]));
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
    expect(addButton()).toHaveTextContent("Add 1 selected to allow-list");
    fireEvent.click(addButton());
    await waitFor(() =>
      expect(add).toHaveBeenCalledWith(
        "web",
        [{ kind: "http", host: "pypi.org", port: 443, access: "read" }],
        false,
      ),
    );

    // npm returns (coverage revoked again): the notice reports it as new, and
    // Refresh must land it unticked — a departed-then-returned row is not the
    // same consent as the tick the user gave it before it left.
    rerender(dialog([pypi, npm]));
    expect(screen.getByRole("status")).toHaveTextContent(
      "1 new endpoint(s) observed since this review — refresh to include them.",
    );
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
    expect(screen.getByRole("checkbox", { name: "npmjs.org:443" })).not.toBeChecked();
    expect(addButton()).toHaveTextContent("Add 1 selected to allow-list");
  });

  it("an access override on a row that STAYS through Refresh is preserved", async () => {
    const add = api.policyAddEndpoints as Mock;
    const { rerender } = render(dialog([pypi]));
    fireEvent.click(screen.getByRole("checkbox", { name: "pypi.org:443" }));
    fireEvent.click(screen.getByRole("radio", { name: "read-write" }));

    rerender(dialog([npm, pypi]));
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
    fireEvent.click(addButton());
    await waitFor(() =>
      expect(add).toHaveBeenCalledWith(
        "web",
        [{ kind: "http", host: "pypi.org", port: 443, access: "read-write" }],
        false,
      ),
    );
  });

  it("Refresh never widens a surviving git row's access when a later push folds into it", async () => {
    const add = api.policyAddEndpoints as Mock;
    const clone = sum({ host: "github.com", last_method: "POST", last_path: "/o/b/git-upload-pack" });
    const push = sum({ host: "github.com", last_method: "POST", last_path: "/o/b/git-receive-pack" });
    const gitDialog = (rows: EndpointSummary[]) => (
      <SeedDialog name="web" rows={rows} enforcing={true} policy={{ ...bare, enforcing: true }}
        onClose={() => {}} onApplied={() => {}} />
    );
    const { rerender } = render(gitDialog([clone]));
    fireEvent.click(screen.getByRole("checkbox", { name: "git clone → github.com/o/b" }));

    rerender(gitDialog([clone, push]));
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));

    // The row is still checked and its label now names the broader op the
    // netlog observed, but the access the user reviewed (read) must survive —
    // the fold must not silently upgrade a read consent to read-write.
    expect(screen.getByRole("checkbox", { name: "git push → github.com/o/b" })).toBeChecked();
    expect(screen.getByRole("radio", { name: "read" })).toBeChecked();

    fireEvent.click(addButton());
    await waitFor(() =>
      expect(add).toHaveBeenCalledWith(
        "web",
        [{ kind: "git", target: "github.com/o/b", access: "read" }],
        false,
      ),
    );
  });

  it("a pin left by Refresh can still be widened explicitly via the access picker", async () => {
    const add = api.policyAddEndpoints as Mock;
    const clone = sum({ host: "github.com", last_method: "POST", last_path: "/o/b/git-upload-pack" });
    const push = sum({ host: "github.com", last_method: "POST", last_path: "/o/b/git-receive-pack" });
    const gitDialog = (rows: EndpointSummary[]) => (
      <SeedDialog name="web" rows={rows} enforcing={true} policy={{ ...bare, enforcing: true }}
        onClose={() => {}} onApplied={() => {}} />
    );
    const { rerender } = render(gitDialog([clone]));
    fireEvent.click(screen.getByRole("checkbox", { name: "git clone → github.com/o/b" }));

    rerender(gitDialog([clone, push]));
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));

    fireEvent.click(screen.getByRole("radio", { name: "read-write" }));
    fireEvent.click(addButton());
    await waitFor(() =>
      expect(add).toHaveBeenCalledWith(
        "web",
        [{ kind: "git", target: "github.com/o/b", access: "read-write" }],
        false,
      ),
    );
  });

  it("Refresh never widens a surviving http row's access when a later write flips its default", async () => {
    const add = api.policyAddEndpoints as Mock;
    const get = sum({ host: "pypi.org", port: 443, last_method: "GET" });
    const post = sum({ host: "pypi.org", port: 443, last_method: "POST" });
    const httpDialog = (rows: EndpointSummary[]) => (
      <SeedDialog name="web" rows={rows} enforcing={true} policy={{ ...bare, enforcing: true }}
        onClose={() => {}} onApplied={() => {}} />
    );
    const { rerender } = render(httpDialog([get]));
    fireEvent.click(screen.getByRole("checkbox", { name: "pypi.org:443" }));

    rerender(httpDialog([post]));
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));

    fireEvent.click(addButton());
    await waitFor(() =>
      expect(add).toHaveBeenCalledWith(
        "web",
        [{ kind: "http", host: "pypi.org", port: 443, access: "read" }],
        false,
      ),
    );
  });

  it("Refresh does not pin access on a surviving row whose default is unchanged", async () => {
    const add = api.policyAddEndpoints as Mock;
    const { rerender } = render(dialog([pypi]));
    fireEvent.click(screen.getByRole("checkbox", { name: "pypi.org:443" }));

    rerender(dialog([npm, pypi]));
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));

    const pypiRow = screen.getByRole("checkbox", { name: "pypi.org:443" }).closest("label")!;
    expect(within(pypiRow).getByRole("radio", { name: "read" })).toBeChecked();
    fireEvent.click(addButton());
    await waitFor(() =>
      expect(add).toHaveBeenCalledWith(
        "web",
        [{ kind: "http", host: "pypi.org", port: 443, access: "read" }],
        false,
      ),
    );
  });
});

describe("buildCandidates", () => {
  it("orders candidates by key regardless of backend order, selectable kinds before raw IPs", () => {
    const a = sum({ host: "pypi.org", port: 443 });
    const b = sum({ host: "npmjs.org", port: 443 });
    const raw = sum({ host: null, dest_ip: "10.0.0.1", port: 80, last_method: null, last_path: null });
    const g = sum({ host: "github.com", last_method: "POST", last_path: "/o/b/git-upload-pack" });
    const keys = (rows: EndpointSummary[]) => buildCandidates(rows, bare).map((c) => c.key);
    expect(keys([raw, a, g, b])).toEqual([
      "git:github.com/o/b",
      "http:npmjs.org:443",
      "http:pypi.org:443",
      "raw-ip:10.0.0.1:80",
    ]);
    expect(keys([b, g, a, raw])).toEqual(keys([raw, a, g, b]));
  });

  it("folds rows that resolve to the same key into one candidate with summed counts, push winning", () => {
    const clone = sum({ host: "github.com", port: 443, last_method: "POST", last_path: "/o/b/git-upload-pack", allow_count: 2, deny_count: 1 });
    const push = sum({ host: "github.com", port: 80, last_method: "POST", last_path: "/o/b/git-receive-pack", allow_count: 3, deny_count: 0 });
    const out = buildCandidates([clone, push], bare);
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({ key: "git:github.com/o/b", allowCount: 5, denyCount: 1, defaultAccess: "read-write" });
    expect(out[0].label).toBe("git push → github.com/o/b");
    expect(buildCandidates([push, clone], bare)[0].label).toBe("git push → github.com/o/b");
  });
});
