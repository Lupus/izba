import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach } from "vitest";
import { NetlogView, relTime, git_repo_from_row } from "../components/NetlogView";
import { api } from "../lib/ipc";
import type { PolicyView } from "../lib/types";

vi.mock("../lib/ipc", () => ({
  api: {
    readNetlog: vi.fn(),
    policyShow: vi.fn(),
    policyAllow: vi.fn(),
    policyBlock: vi.fn(),
    policyEnable: vi.fn(),
    policyGitAllow: vi.fn(),
    policyGitBlock: vi.fn(),
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
  mockPolicy({ enforcing: true, allow: [], git: [] });
  (api.readNetlog as ReturnType<typeof vi.fn>).mockResolvedValue([allowedNamed, deniedRawIp]);
});

describe("NetlogView", () => {
  it("offers Block on a host the policy already allows", async () => {
    mockPolicy({ enforcing: true, allow: ["api.x.com"], git: [] }); // bare host ⇒ 80, 443
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
      git: [],
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
    mockPolicy({ enforcing: false, allow: [], git: [] });
    render(<NetlogView name="web" />);
    const btn = await screen.findByRole("button", { name: /enable firewall/i });
    fireEvent.click(btn);
    await waitFor(() => expect(api.policyEnable).toHaveBeenCalledWith("web"));
  });

  it("orders rows deterministically by recency then host:port, not backend order", async () => {
    // Two endpoints with the SAME last_seen_ms — the backend's HashMap can
    // hand them back in either order between polls (the 'jumping' bug). The
    // view must impose a stable tiebreaker so the DOM order never flips.
    // dest_ip is inherited from the fixture — these rows resolve by host, so the
    // value is irrelevant here (and avoids hardcoded-IP-literal lint noise).
    const beta = { ...allowedNamed, host: "beta.example", port: 443, last_seen_ms: 100 };
    const alpha = { ...allowedNamed, host: "alpha.example", port: 443, last_seen_ms: 100 };
    // Hand them to the view in the 'wrong' (beta-first) order.
    (api.readNetlog as ReturnType<typeof vi.fn>).mockResolvedValue([beta, alpha]);
    render(<NetlogView name="web" />);
    await screen.findByText("alpha.example");
    const cells = screen.getAllByText(/example$/);
    // Same recency ⇒ alphabetical host wins: alpha before beta.
    expect(cells.map((c) => c.textContent)).toEqual(["alpha.example", "beta.example"]);
  });

  it("shows a Last activity column with a relative time", async () => {
    render(<NetlogView name="web" />);
    await screen.findByText("api.x.com");
    expect(screen.getByRole("columnheader", { name: /last activity/i })).toBeInTheDocument();
  });

  it("keeps the Last activity column live via a 1s clock, independent of polling", async () => {
    // last_seen = render time ⇒ the label starts at "just now". With polling
    // effectively off (huge interval, so only the immediate first read fires),
    // the only thing that can advance the relative time is the 1-second clock —
    // exactly the parked-pointer case where hover-pause freezes the rows but the
    // Last-activity labels must keep ticking.
    const fresh = { ...allowedNamed, host: "fresh.example", last_seen_ms: Date.now() };
    (api.readNetlog as ReturnType<typeof vi.fn>).mockResolvedValue([fresh]);
    render(<NetlogView name="web" pollMs={10_000_000} />);
    await screen.findByText("fresh.example");
    await waitFor(() => expect(screen.getByText(/\ds ago/)).toBeInTheDocument(), {
      timeout: 4000,
    });
  });

  it("pauses polling while the pointer hovers the table", async () => {
    const read = api.readNetlog as ReturnType<typeof vi.fn>;
    render(<NetlogView name="web" pollMs={20} />);
    // Let a couple of poll ticks accrue.
    await waitFor(() => expect(read.mock.calls.length).toBeGreaterThan(2));
    fireEvent.mouseEnter(screen.getByRole("table"));
    const frozen = read.mock.calls.length;
    // The paused hint appears (it lives in an always-present footer below the
    // table, so showing it never reflows the rows).
    expect(screen.getByText(/auto-refresh paused/i)).toBeInTheDocument();
    // Across several poll intervals, no new reads fire while hovering.
    await new Promise((r) => setTimeout(r, 120));
    expect(read.mock.calls.length).toBe(frozen);
    // Leaving resumes polling and clears the hint.
    fireEvent.mouseLeave(screen.getByRole("table"));
    expect(screen.queryByText(/auto-refresh paused/i)).not.toBeInTheDocument();
    await waitFor(() => expect(read.mock.calls.length).toBeGreaterThan(frozen));
  });

  // Factory for git push row fixtures: only verdict/counts differ across tests.
  function makeGitPushRow(verdict: "allow" | "deny", allow_count: number, deny_count: number) {
    return {
      host: "github.com", dest_ip: "140.82.121.4", port: 443, tier: "l7",
      verdict, allow_count, deny_count,
      first_seen_ms: 1, last_seen_ms: 9,
      last_method: "POST", last_path: "/o/a/git-receive-pack",
    };
  }

  it("renders a git push row and offers Allow write", async () => {
    (api.readNetlog as ReturnType<typeof vi.fn>).mockResolvedValue([makeGitPushRow("allow", 1, 0)]);
    mockPolicy({ enforcing: true, allow: [], git: [] });
    (api.policyGitAllow as ReturnType<typeof vi.fn>).mockResolvedValue(undefined);
    render(<NetlogView name="sb" />);
    // Should render "git push" label
    expect(await screen.findByText(/git push/i)).toBeInTheDocument();
    // Should show destination repo
    expect(screen.getByText(/github\.com\/o\/a/i)).toBeInTheDocument();
    // "Allow write" button calls policyGitAllow with write=true
    const btn = screen.getByRole("button", { name: /allow write/i });
    fireEvent.click(btn);
    await waitFor(() =>
      expect(api.policyGitAllow).toHaveBeenCalledWith("sb", "github.com/o/a", true),
    );
  });

  it("renders a git clone row and offers Allow read", async () => {
    const gitCloneRow = {
      host: "github.com", dest_ip: "140.82.121.4", port: 443, tier: "l7",
      verdict: "deny" as const, allow_count: 0, deny_count: 1,
      first_seen_ms: 1, last_seen_ms: 9,
      last_method: "GET", last_path: "/owner/repo.git/info/refs?service=git-upload-pack",
    };
    (api.readNetlog as ReturnType<typeof vi.fn>).mockResolvedValue([gitCloneRow]);
    mockPolicy({ enforcing: true, allow: [], git: [] });
    (api.policyGitAllow as ReturnType<typeof vi.fn>).mockResolvedValue(undefined);
    render(<NetlogView name="sb" />);
    expect(await screen.findByText(/git clone/i)).toBeInTheDocument();
    const btn = screen.getByRole("button", { name: /allow read/i });
    fireEvent.click(btn);
    await waitFor(() =>
      expect(api.policyGitAllow).toHaveBeenCalledWith("sb", "github.com/owner/repo", false),
    );
  });

  it("git row Policy column shows neutral git indicator, not host-derived allowed/blocked", async () => {
    // A git push row where host is NOT in the host allow-list.
    // The host-derived status would be "blocked" (wrong — git ops are governed
    // by view.git rules, not the host allow-list).  The Policy column must show
    // a neutral git indicator instead of either "allowed" or "blocked".
    (api.readNetlog as ReturnType<typeof vi.fn>).mockResolvedValue([makeGitPushRow("deny", 0, 1)]);
    // allow: [] → host-derived status would be "blocked", but that's wrong for git rows.
    mockPolicy({ enforcing: true, allow: [], git: [] });
    render(<NetlogView name="sb" />);
    await screen.findByText(/git push/i);
    // Must NOT render the host-derived "blocked" badge.
    expect(screen.queryByText("blocked")).not.toBeInTheDocument();
    // Must NOT render the host-derived "allowed" badge.
    expect(screen.queryByText("allowed")).not.toBeInTheDocument();
    // Must render a neutral git indicator (role-agnostic text match).
    expect(screen.getByText(/git rule/i)).toBeInTheDocument();
  });

  it("Block on a git row calls policyGitBlock", async () => {
    (api.readNetlog as ReturnType<typeof vi.fn>).mockResolvedValue([makeGitPushRow("allow", 1, 0)]);
    mockPolicy({ enforcing: true, allow: [], git: [] });
    (api.policyGitBlock as ReturnType<typeof vi.fn>).mockResolvedValue(undefined);
    render(<NetlogView name="sb" />);
    await screen.findByText(/git push/i);
    const btn = screen.getByRole("button", { name: /^block$/i });
    fireEvent.click(btn);
    await waitFor(() =>
      expect(api.policyGitBlock).toHaveBeenCalledWith("sb", "github.com/o/a"),
    );
  });
});

describe("relTime", () => {
  const now = 1_000_000_000;
  it("renders sub-second as 'just now'", () => {
    expect(relTime(now - 200, now)).toBe("just now");
  });
  it("renders seconds, minutes, hours, days", () => {
    expect(relTime(now - 5_000, now)).toBe("5s ago");
    expect(relTime(now - 3 * 60_000, now)).toBe("3m ago");
    expect(relTime(now - 2 * 3_600_000, now)).toBe("2h ago");
    expect(relTime(now - 4 * 86_400_000, now)).toBe("4d ago");
  });
});

describe("git_repo_from_row", () => {
  it("extracts repo from git-receive-pack path", () => {
    expect(git_repo_from_row("github.com", "/o/a/git-receive-pack")).toBe("github.com/o/a");
  });
  it("extracts repo from git-upload-pack path", () => {
    expect(git_repo_from_row("github.com", "/o/a/git-upload-pack")).toBe("github.com/o/a");
  });
  it("extracts repo from info/refs path with .git suffix", () => {
    expect(git_repo_from_row("github.com", "/owner/repo.git/info/refs?service=git-upload-pack"))
      .toBe("github.com/owner/repo");
  });
  it("returns null for non-git paths", () => {
    expect(git_repo_from_row("github.com", "/some/other/api")).toBeNull();
  });
  it("returns null when host is null", () => {
    expect(git_repo_from_row(null, "/o/a/git-receive-pack")).toBeNull();
  });
});
