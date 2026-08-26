import { act, render, screen, fireEvent, waitFor } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach, type Mock } from "vitest";
import { NetlogView, relTime } from "../components/NetlogView";
import { git_repo_from_row } from "../lib/git";
import { api } from "../lib/ipc";
import type { EndpointSummary, PolicyView } from "../lib/types";

vi.mock("../lib/ipc", () => ({
  api: {
    readNetlog: vi.fn(),
    policyShow: vi.fn(),
    policyAllow: vi.fn(),
    policyBlock: vi.fn(),
    policyGitAllow: vi.fn(),
    policyGitBlock: vi.fn(),
    policySetEnforce: vi.fn(),
    policyAddEndpoints: vi.fn(),
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

/** Build a minimal EndpointSummary with optional overrides. */
function sum(overrides: Partial<EndpointSummary>): EndpointSummary {
  return {
    host: "a.com", dest_ip: "1.2.3.4", port: 443, tier: "l7", verdict: "allow",
    allow_count: 1, deny_count: 0, first_seen_ms: 1, last_seen_ms: 9,
    last_method: "GET", last_path: "/",
    ...overrides,
  };
}

function mockPolicy(p: PolicyView) {
  (api.policyShow as ReturnType<typeof vi.fn>).mockResolvedValue(p);
}

beforeEach(() => {
  vi.clearAllMocks();
  mockPolicy({ enforcing: true, allow: [], git: [] });
  (api.readNetlog as ReturnType<typeof vi.fn>).mockResolvedValue([allowedNamed, deniedRawIp]);
  (api.policySetEnforce as ReturnType<typeof vi.fn>).mockResolvedValue(undefined);
  (api.policyAddEndpoints as ReturnType<typeof vi.fn>).mockResolvedValue(undefined);
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

  it("shows the Firewall OFF banner for a bare sandbox with Review traffic button", async () => {
    mockPolicy({ enforcing: false, allow: [], git: [] });
    render(<NetlogView name="web" />);
    // Banner must mention "Firewall OFF"
    expect(await screen.findByText(/Firewall OFF/)).toBeInTheDocument();
    // "Review observed traffic" button must be present
    const btn = screen.getByRole("button", { name: /review observed traffic/i });
    expect(btn).toBeInTheDocument();
  });

  it("off-state banner is honest (no 'all allowed', shows blocked-while-enforcing)", async () => {
    (api.policyShow as Mock).mockResolvedValue({ enforcing: false, allow: [], git: [] });
    (api.readNetlog as Mock).mockResolvedValue([
      sum({ host: "a.com", port: 443, deny_count: 3 }), sum({ host: "b.com", port: 443 }),
    ]);
    render(<NetlogView name="web" />);
    expect(await screen.findByText(/Firewall OFF/)).toBeInTheDocument();
    expect(screen.getByText(/1 were blocked while enforcing/)).toBeInTheDocument();
    expect(screen.queryByText(/all allowed/)).toBeNull();
  });

  it("a git row reflects its policy access and offers Block", async () => {
    (api.policyShow as Mock).mockResolvedValue({ enforcing: true, allow: [], git: [{ repo: "github.com/o/a", access: "read" }] });
    (api.readNetlog as Mock).mockResolvedValue([ sum({ host: "github.com", port: 443, last_method: "POST", last_path: "/o/a/git-upload-pack" }) ]);
    render(<NetlogView name="web" />);
    expect(await screen.findByText("git → github.com/o/a")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^Block$/ })).toBeInTheDocument();
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

  it("renders a git push row with 'git → repo' label and offers Allow write", async () => {
    (api.readNetlog as ReturnType<typeof vi.fn>).mockResolvedValue([makeGitPushRow("allow", 1, 0)]);
    mockPolicy({ enforcing: true, allow: [], git: [] });
    (api.policyGitAllow as ReturnType<typeof vi.fn>).mockResolvedValue(undefined);
    render(<NetlogView name="sb" />);
    // Should render "git → repo" label (new format per Task 8)
    expect(await screen.findByText("git → github.com/o/a")).toBeInTheDocument();
    // "Allow write" button calls policyGitAllow with write=true
    const btn = screen.getByRole("button", { name: /allow write/i });
    fireEvent.click(btn);
    await waitFor(() =>
      expect(api.policyGitAllow).toHaveBeenCalledWith("sb", "github.com/o/a", true),
    );
  });

  it("renders a git clone row with 'git → repo' label and offers Allow read", async () => {
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
    expect(await screen.findByText("git → github.com/owner/repo")).toBeInTheDocument();
    const btn = screen.getByRole("button", { name: /allow read/i });
    fireEvent.click(btn);
    await waitFor(() =>
      expect(api.policyGitAllow).toHaveBeenCalledWith("sb", "github.com/owner/repo", false),
    );
  });

  it("git row Policy column shows access when rule exists, or 'blocked' when enforcing without rule", async () => {
    // A git push row where host is NOT in the host allow-list, and no git rule exists.
    // The Policy column must show "blocked" (not the host-derived "blocked" from host rules).
    (api.readNetlog as ReturnType<typeof vi.fn>).mockResolvedValue([makeGitPushRow("deny", 0, 1)]);
    mockPolicy({ enforcing: true, allow: [], git: [] });
    render(<NetlogView name="sb" />);
    await screen.findByText(/git → github\.com\/o\/a/);
    // With enforcing=true and no git rule, git rows show "blocked"
    expect(screen.getByText("blocked")).toBeInTheDocument();
    // Must NOT render the misleading "git rule" generic text.
    expect(screen.queryByText("git rule")).not.toBeInTheDocument();
    // Must NOT render "allowed" from the host allow-list path.
    expect(screen.queryByText("allowed")).not.toBeInTheDocument();
  });

  it("Block on a git row calls policyGitBlock", async () => {
    (api.readNetlog as ReturnType<typeof vi.fn>).mockResolvedValue([makeGitPushRow("allow", 1, 0)]);
    mockPolicy({ enforcing: true, allow: [], git: [] });
    (api.policyGitBlock as ReturnType<typeof vi.fn>).mockResolvedValue(undefined);
    render(<NetlogView name="sb" />);
    await screen.findByText(/git → github\.com\/o\/a/);
    // No git rule → Block button is NOT shown (call-to-action for Allow-read/Allow-write instead)
    // Block is only shown when access !== null (a rule exists).
    expect(screen.queryByRole("button", { name: /^Block$/i })).not.toBeInTheDocument();
  });

  it("Block on a git row with existing rule calls policyGitBlock", async () => {
    (api.readNetlog as ReturnType<typeof vi.fn>).mockResolvedValue([makeGitPushRow("allow", 1, 0)]);
    mockPolicy({ enforcing: true, allow: [], git: [{ repo: "github.com/o/a", access: "read" }] });
    (api.policyGitBlock as ReturnType<typeof vi.fn>).mockResolvedValue(undefined);
    render(<NetlogView name="sb" />);
    await screen.findByText(/git → github\.com\/o\/a/);
    const btn = screen.getByRole("button", { name: /^Block$/i });
    fireEvent.click(btn);
    await waitFor(() =>
      expect(api.policyGitBlock).toHaveBeenCalledWith("sb", "github.com/o/a"),
    );
  });

  it("does not crash (white screen) when an allow entry omits ports", async () => {
    // Regression: the backend serializes a Scoped entry whose ports equal the
    // web defaults with NO `ports` field. allowKeys must not blow up rendering.
    mockPolicy({
      enforcing: true,
      allow: [{ host: "pypi.org", access: "read" } as unknown as PolicyView["allow"][number]],
      git: [],
    });
    (api.readNetlog as Mock).mockResolvedValue([sum({ host: "pypi.org", port: 443 })]);
    render(<NetlogView name="web" />);
    expect(await screen.findByText(/Firewall ON/)).toBeInTheDocument();
    // pypi.org:443 should read as "allowed" (web-default ports applied).
    expect(await screen.findByText(/^allowed$/)).toBeInTheDocument();
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

/** DEEP-F2 — the Netlog tab must not report a firewall posture it never read.
 *
 *  `policy` initialises to `null` and `enforcing` was `policy?.enforcing ??
 *  false`, so before `policyShow` resolved — and for as long as it kept
 *  failing, since `refresh` is a `Promise.all` and either half can reject —
 *  the banner announced "Firewall OFF · all egress currently allowed" for a
 *  sandbox that may well be enforcing, with the enforce toggle live. From that
 *  window `toggleEnforce` computes `next = !false = true`, so the write
 *  direction is ALWAYS on: it cannot disarm, but it can arm a bare sandbox
 *  onto an empty allow-list, and it misreports the posture of an enforcing one
 *  (advertised-posture ≠ enforced-posture).
 *
 *  Assertions are on the API mock, never on a `disabled` attribute; each
 *  refusal test also asserts the refusal is visible so it cannot pass
 *  vacuously. `FirewallStatus` already renders `…` for exactly this data —
 *  this pins the same honesty here. */
describe("NetlogView load state", () => {
  /** A `policyShow` that never settles — the "still loading" window. */
  function pendingPolicyShow() {
    (api.policyShow as Mock).mockReturnValue(new Promise(() => {}));
  }

  it("refuses to toggle enforcement before the policy has loaded (policySetEnforce never called)", async () => {
    pendingPolicyShow();
    render(<NetlogView name="web" />);
    // By accessible NAME, not by role: an unguarded build still renders the
    // switch here (and this click makes it write `true`), a guarded one
    // renders a control that refuses. Both must answer to "Enforce firewall".
    fireEvent.click(screen.getByLabelText(/enforce firewall/i));
    expect(api.policySetEnforce).not.toHaveBeenCalled();
    await waitFor(() => expect(screen.getByText(/refus/i)).toBeInTheDocument());
    expect(api.policySetEnforce).not.toHaveBeenCalled();
  });

  it("refuses to toggle enforcement after the policy load failed (policySetEnforce never called)", async () => {
    (api.policyShow as Mock).mockRejectedValue(new Error("daemon unreachable"));
    render(<NetlogView name="web" />);
    await screen.findByText(/daemon unreachable/i);
    // By accessible NAME, not by role: an unguarded build still renders the
    // switch here (and this click makes it write `true`), a guarded one
    // renders a control that refuses. Both must answer to "Enforce firewall".
    fireEvent.click(screen.getByLabelText(/enforce firewall/i));
    expect(api.policySetEnforce).not.toHaveBeenCalled();
    await waitFor(() => expect(screen.getByText(/refus/i)).toBeInTheDocument());
    expect(api.policySetEnforce).not.toHaveBeenCalled();
  });

  it("claims no firewall posture while the policy is loading", () => {
    pendingPolicyShow();
    render(<NetlogView name="web" />);
    expect(screen.queryByText(/firewall off/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/firewall on/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/all egress currently allowed/i)).not.toBeInTheDocument();
    expect(screen.getByText(/posture unknown/i)).toBeInTheDocument();
  });

  it("claims no firewall posture after the policy load failed", async () => {
    (api.policyShow as Mock).mockRejectedValue(new Error("daemon unreachable"));
    render(<NetlogView name="web" />);
    await screen.findByText(/daemon unreachable/i);
    expect(screen.queryByText(/firewall off/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/firewall on/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/all egress currently allowed/i)).not.toBeInTheDocument();
    expect(screen.getByText(/posture unknown/i)).toBeInTheDocument();
  });

  it("does not claim an empty netlog before the netlog has been read", () => {
    pendingPolicyShow();
    render(<NetlogView name="web" />);
    expect(screen.queryByText(/no egress recorded yet/i)).not.toBeInTheDocument();
  });

  it("still reports, and still toggles, a genuinely loaded off posture", async () => {
    mockPolicy({ enforcing: false, allow: [], git: [] });
    render(<NetlogView name="web" />);
    expect(await screen.findByText(/Firewall OFF/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("switch", { name: /enforce firewall/i }));
    await waitFor(() => expect(api.policySetEnforce).toHaveBeenCalledWith("web", true));
  });
});

/** DEEP-F2b (PR #264 review) — a sandbox switch must not pair the NEW
 *  sandbox's name with the PREVIOUS one's posture.
 *
 *  `refresh` is keyed on `name`, but nothing reset the state the previous
 *  sandbox's answer had already filled in. So from the moment the selection
 *  changed until the new fetch resolved, the tab kept `loadState: "ready"`,
 *  the old `policy` and the old `rows` — and every control stayed live. A
 *  click in that window sends `policySetEnforce(NEW_NAME, !OLD_POSTURE)`:
 *  the sandbox being written is not the sandbox the posture came from, so the
 *  toggle can now write OFF as easily as ON — this window can DISARM a
 *  firewall, which the unloaded window could not.
 *
 *  Two shapes of the same hazard are pinned here: the switch itself, and a
 *  SLOW answer for the sandbox the tab already left landing afterwards
 *  (mirroring `DisplayTab`'s "never paints a slow answer" guard). Both assert
 *  on the API mock, never on a disabled attribute, and a test that only
 *  checked the settled end state would pass without the guard. */
describe("NetlogView sandbox switch", () => {
  const enforcingWeb: PolicyView = { enforcing: true, allow: ["api.x.com"], git: [] };

  /** `web` answers; every other sandbox hangs — that IS the switch window. */
  function webAnswersOthersHang() {
    (api.policyShow as Mock).mockImplementation((n: string) =>
      n === "web" ? Promise.resolve(enforcingWeb) : new Promise(() => {}),
    );
  }

  it("stops presenting the previous sandbox's posture the moment the sandbox changes", async () => {
    webAnswersOthersHang();
    const { rerender } = render(<NetlogView name="web" />);
    expect(await screen.findByText(/Firewall ON/)).toBeInTheDocument();

    rerender(<NetlogView name="db" />);

    expect(screen.queryByText(/Firewall ON/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Firewall OFF/)).not.toBeInTheDocument();
    expect(screen.getByText(/posture unknown/i)).toBeInTheDocument();
  });

  it("refuses an enforce write during a sandbox switch (policySetEnforce never called)", async () => {
    webAnswersOthersHang();
    const { rerender } = render(<NetlogView name="web" />);
    await screen.findByText(/Firewall ON/);

    rerender(<NetlogView name="db" />);

    // Unguarded, this click writes `policySetEnforce("db", false)` — the NEW
    // sandbox, flipped from the OLD sandbox's posture. That is a DISARM.
    fireEvent.click(screen.getByLabelText(/enforce firewall/i));
    expect(api.policySetEnforce).not.toHaveBeenCalled();
    await waitFor(() => expect(screen.getByText(/refus/i)).toBeInTheDocument());
    expect(api.policySetEnforce).not.toHaveBeenCalled();
  });

  it("withdraws the previous sandbox's rows and their policy actions on a switch", async () => {
    webAnswersOthersHang();
    const { rerender } = render(<NetlogView name="web" />);
    // `web` is enforcing and allows api.x.com, so the row offers Block.
    await screen.findByRole("button", { name: /block api\.x\.com/i });

    rerender(<NetlogView name="db" />);

    // The row-policy writes share the enforce guard structurally: they render
    // only under `enforcing`, which is derived from `policy` — cleared here.
    // This test is what keeps that "structural" claim honest.
    expect(screen.queryByRole("button", { name: /block api\.x\.com/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /allow api\.x\.com/i })).not.toBeInTheDocument();
    expect(screen.queryByText("api.x.com")).not.toBeInTheDocument();
    expect(api.policyBlock).not.toHaveBeenCalled();
    expect(api.policyAllow).not.toHaveBeenCalled();
  });

  it("never paints a slow answer for the sandbox the tab already left", async () => {
    let answerWeb: (p: PolicyView) => void = () => {};
    (api.policyShow as Mock).mockImplementation((n: string) =>
      n === "web"
        ? new Promise<PolicyView>((res) => {
            answerWeb = res;
          })
        : new Promise(() => {}),
    );
    const { rerender } = render(<NetlogView name="web" />);
    await waitFor(() => expect(api.policyShow).toHaveBeenCalledWith("web"));

    rerender(<NetlogView name="db" />);
    // `web`'s answer arrives AFTER the tab moved on: it describes a sandbox
    // that is no longer selected and must never be painted as `db`'s.
    await act(async () => {
      answerWeb(enforcingWeb);
    });

    expect(screen.queryByText(/Firewall ON/)).not.toBeInTheDocument();
    expect(screen.getByText(/posture unknown/i)).toBeInTheDocument();
    expect(screen.queryByText("api.x.com")).not.toBeInTheDocument();
  });
});
