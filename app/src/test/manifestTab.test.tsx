import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach, type Mock } from "vitest";
import { ManifestTab } from "../components/ManifestTab";
import { api } from "../lib/ipc";
import type { PromoteView } from "../lib/types";

vi.mock("../lib/ipc", () => ({
  api: {
    manifestDiff: vi.fn(),
    manifestExport: vi.fn(),
    manifestPromote: vi.fn(),
    // Consumed by the WorkspacePath line at the top of the tab.
    inspect: vi.fn().mockResolvedValue({
      name: "web",
      image: "ubuntu:24.04",
      status: "running",
      workspace: "/home/u/proj",
      ports: [],
      volumes: [],
    }),
  },
}));

function promoteView(overrides: Partial<PromoteView> = {}): PromoteView {
  return {
    state: "in_sync",
    applied: [],
    needs_restart: false,
    restarted: false,
    stopped: false,
    warnings: [],
    ...overrides,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
});

// The four direction-agnostic banner strings, byte-identical to
// `ManifestTab.tsx`'s non-weakening copy — other in-repo consumers
// (app/e2e/manifest.spec.ts, hack/dogfood/journeys/manifest-gui.json) assert
// them verbatim, so they must not drift.
const IN_SYNC_BANNER = "In sync — izba.yml and managed settings match.";
const REPO_AHEAD_BANNER = "izba.yml has changes not yet applied. Review below, then Promote.";
const MANAGED_AHEAD_BANNER = "Live settings have drifted from izba.yml. Export to capture them.";
const DIVERGED_BANNER =
  "Both izba.yml and managed settings changed. Promote applies izba.yml; Export overwrites it.";

// The direction-AWARE copy (#241). These four are byte-shared with
// `crates/izba-cli/src/commands/diff.rs`'s `next:` line — the two surfaces
// must never recommend contradictory actions for identical input.
const REPO_AHEAD_WEAKENS_BANNER =
  "izba.yml would weaken egress relative to the current managed settings. " +
  "Keep the managed settings as they are — Promote only if you intend to relax enforcement.";
const MANAGED_AHEAD_WEAKENS_BANNER =
  "izba.yml would weaken egress relative to the current managed settings. " +
  "Export to capture the managed settings into izba.yml.";
const DIVERGED_WEAKENS_BANNER =
  "izba.yml would weaken egress relative to the current managed settings. " +
  "Export to capture the managed settings into izba.yml — or Promote only if you intend to " +
  "relax enforcement.";
const DIVERGED_NO_DELTAS_BANNER =
  "Both izba.yml and managed settings changed since the last reconcile, but they now hold the " +
  "same values — there is nothing to apply. Export to realign izba.yml and clear the drift.";

/** The canonical weakening delta: the live sandbox enforces, izba.yml asks it
 *  not to. `from` is managed truth, `to` is the izba.yml proposal. */
const WEAKENING_DELTA = {
  field: "policy.egress.enforce",
  from: "true",
  to: "false",
  class: "live" as const,
  weakens_egress: true,
};

/** A non-egress drift — the no-regression control. */
const BENIGN_DELTA = {
  field: "cpus",
  from: "2",
  to: "4",
  class: "restart" as const,
  weakens_egress: false,
};

/** An egress drift that STRENGTHENS: izba.yml adds a host the managed
 *  allow-list lacks, so promoting it does not relax anything. */
const STRENGTHENING_EGRESS_DELTA = {
  field: "egress",
  from: "enforce: true\nallow:\n- host: a.com",
  to: "enforce: true\nallow:\n- host: a.com\n- host: b.com",
  class: "live" as const,
  weakens_egress: false,
};

describe("ManifestTab", () => {
  it("fetches on mount and renders the weakening repo_ahead banner + the delta row", async () => {
    (api.manifestDiff as Mock).mockResolvedValue({
      state: "repo_ahead",
      deltas: [
        {
          field: "policy.egress.enforce",
          from: "true",
          to: "false",
          class: "live",
          weakens_egress: true,
        },
      ],
    });
    render(<ManifestTab name="web" running={true} />);

    // The delta weakens egress, so the banner must NOT recommend Promote
    // (#241) — the direction-aware copy is asserted in full by the banner
    // matrix below; here it just has to be the weakening one.
    expect(await screen.findByText(REPO_AHEAD_WEAKENS_BANNER)).toBeInTheDocument();
    expect(screen.queryByText(REPO_AHEAD_BANNER)).not.toBeInTheDocument();
    expect(screen.getByText("policy.egress.enforce")).toBeInTheDocument();
    expect(screen.getByText("live")).toBeInTheDocument();
    expect(screen.getByText("⚠ weakens egress")).toBeInTheDocument();
    expect(api.manifestDiff).toHaveBeenCalledWith("web");
  });

  it("shows the sandbox's workspace path so the user can locate izba.yml", async () => {
    (api.manifestDiff as Mock).mockResolvedValue({ state: "in_sync", deltas: [] });
    render(<ManifestTab name="web" running={true} />);

    expect(await screen.findByText("/home/u/proj")).toBeInTheDocument();
    expect(api.inspect).toHaveBeenCalledWith("web");
  });

  it("renders a multi-line delta line-by-line and highlights only the added line", async () => {
    // The field report: egress YAML rendered as one collapsed wall of text
    // with no indication of what actually differs. Each line must be its own
    // element, common lines plain, the one added line green on the To side.
    (api.manifestDiff as Mock).mockResolvedValue({
      state: "repo_ahead",
      deltas: [
        {
          field: "egress",
          from: "enforce: true\nallow:\n- host: a.com\n",
          to: "enforce: true\nallow:\n- host: a.com\n- host: b.com\n",
          class: "live",
          weakens_egress: true,
        },
      ],
    });
    render(<ManifestTab name="web" running={true} />);
    await screen.findByText("egress");

    // Common lines appear once per side, unhighlighted.
    const common = screen.getAllByText("- host: a.com");
    expect(common).toHaveLength(2);
    for (const el of common) {
      expect(el.className).not.toContain("bg-success");
      expect(el.className).not.toContain("bg-destructive");
    }
    // Only the added line is highlighted, on the To side.
    const added = screen.getByText("- host: b.com");
    expect(added.className).toContain("bg-success");
    // Column headers orient the two sides.
    expect(screen.getByText("From (managed)")).toBeInTheDocument();
    expect(screen.getByText("To (izba.yml)")).toBeInTheDocument();
  });

  it("names which side is the managed truth and which comes from izba.yml", async () => {
    // A bare From/To says nothing about WHICH side the daemon is actually
    // running: the diff is computed as diff(managed, repo), so From is the
    // live managed truth and To is the izba.yml proposal (issue #240).
    (api.manifestDiff as Mock).mockResolvedValue({
      state: "repo_ahead",
      deltas: [{ field: "cpus", from: "2", to: "4", class: "restart", weakens_egress: false }],
    });
    render(<ManifestTab name="web" running={true} />);
    await screen.findByText("cpus");

    const managed = screen.getByText("From (managed)");
    const repo = screen.getByText("To (izba.yml)");
    const grid = managed.parentElement!;
    expect(repo.parentElement).toBe(grid);
    // Column ORDER is unchanged — managed left, izba.yml right — and each
    // heading sits directly above its own side's value.
    expect(Array.from(grid.children).map((c) => c.textContent).slice(0, 4)).toEqual([
      "From (managed)",
      "To (izba.yml)",
      "2",
      "4",
    ]);
  });

  it("labels both sides of a MULTI-LINE delta value", async () => {
    // The block form is where a mislabelled side is hardest to spot: many
    // lines, no per-line orientation. The heading must still bind to the
    // column its lines are actually rendered in.
    (api.manifestDiff as Mock).mockResolvedValue({
      state: "repo_ahead",
      deltas: [
        {
          field: "egress",
          from: "enforce: true\nallow:\n- host: managed-only.com",
          to: "enforce: true\nallow:\n- host: repo-only.com",
          class: "live",
          weakens_egress: true,
        },
      ],
    });
    render(<ManifestTab name="web" running={true} />);
    await screen.findByText("egress");

    const managed = screen.getByText("From (managed)");
    const repo = screen.getByText("To (izba.yml)");
    const cells = Array.from(managed.parentElement!.children);
    expect(cells.indexOf(managed)).toBe(0);
    expect(cells.indexOf(repo)).toBe(1);
    // The grid alternates managed/izba.yml cells, so an even index sits under
    // the managed heading and an odd index under the izba.yml one. The line
    // that exists only in managed truth must land on the managed side, and
    // the line that exists only in izba.yml on the izba.yml side.
    expect(cells.indexOf(screen.getByText("- host: managed-only.com")) % 2).toBe(0);
    expect(cells.indexOf(screen.getByText("- host: repo-only.com")) % 2).toBe(1);
  });

  it("highlights a removed line on the From side", async () => {
    (api.manifestDiff as Mock).mockResolvedValue({
      state: "repo_ahead",
      deltas: [
        {
          field: "ports",
          from: "127.0.0.1:8080:80\n127.0.0.1:9000:90",
          to: "127.0.0.1:8080:80",
          class: "live",
          weakens_egress: false,
        },
      ],
    });
    render(<ManifestTab name="web" running={true} />);
    await screen.findByText("ports");

    const removed = screen.getByText("127.0.0.1:9000:90");
    expect(removed.className).toContain("bg-destructive");
    const kept = screen.getAllByText("127.0.0.1:8080:80");
    expect(kept).toHaveLength(2);
    for (const el of kept) {
      expect(el.className).not.toContain("bg-destructive");
      expect(el.className).not.toContain("bg-success");
    }
  });

  it("renders the in_sync banner and disables Promote/Export with hint titles", async () => {
    (api.manifestDiff as Mock).mockResolvedValue({ state: "in_sync", deltas: [] });
    render(<ManifestTab name="web" running={true} />);

    expect(await screen.findByText("In sync — izba.yml and managed settings match.")).toBeInTheDocument();
    expect(
      screen.getByText("No field changes between izba.yml and managed settings."),
    ).toBeInTheDocument();

    const promote = screen.getByRole("button", { name: /^promote…$/i });
    expect(promote).toBeDisabled();
    expect(promote).toHaveAttribute(
      "title",
      "Nothing to promote — izba.yml has no unapplied changes.",
    );

    const exportBtn = screen.getByRole("button", { name: /^export to izba\.yml$/i });
    expect(exportBtn).toBeDisabled();
    expect(exportBtn).toHaveAttribute("title", "Nothing to export — no managed-side drift.");
  });

  it("enables Export on managed_ahead, reports the exported path, and refetches the diff so the banner is no longer stale", async () => {
    (api.manifestDiff as Mock).mockResolvedValue({ state: "managed_ahead", deltas: [] });
    (api.manifestExport as Mock).mockResolvedValue("/ws/izba.yml");
    render(<ManifestTab name="web" running={true} />);

    const exportBtn = await screen.findByRole("button", { name: /^export to izba\.yml$/i });
    expect(exportBtn).not.toBeDisabled();
    // Promote stays disabled — managed_ahead has nothing repo-side to promote.
    expect(screen.getByRole("button", { name: /^promote…$/i })).toBeDisabled();
    expect(api.manifestDiff).toHaveBeenCalledTimes(1);

    // The diff flips to in_sync once the export lands — mirrors the real
    // backend, where manifest_export writes izba.yml to match managed truth.
    (api.manifestDiff as Mock).mockResolvedValue({ state: "in_sync", deltas: [] });
    fireEvent.click(exportBtn);
    await waitFor(() => expect(api.manifestExport).toHaveBeenCalledWith("web"));

    // The export confirmation must survive the post-export refetch...
    expect(await screen.findByText("Exported to /ws/izba.yml")).toBeInTheDocument();
    // ...and manifestDiff must have been re-called (not left showing the
    // stale managed_ahead banner/digest) so the in_sync banner now shows too.
    await waitFor(() => expect(api.manifestDiff).toHaveBeenCalledTimes(2));
    expect(
      await screen.findByText("In sync — izba.yml and managed settings match."),
    ).toBeInTheDocument();
    expect(screen.getByText("Exported to /ws/izba.yml")).toBeInTheDocument();
  });

  it("enables both Promote and Export on diverged", async () => {
    // A non-weakening delta: `diverged` with an EMPTY delta list is its own
    // banner case (#241 — "nothing to apply"), covered in the matrix below.
    (api.manifestDiff as Mock).mockResolvedValue({ state: "diverged", deltas: [BENIGN_DELTA] });
    render(<ManifestTab name="web" running={true} />);

    expect(await screen.findByText(DIVERGED_BANNER)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^promote…$/i })).not.toBeDisabled();
    expect(screen.getByRole("button", { name: /^export to izba\.yml$/i })).not.toBeDisabled();
  });

  it("shows missing-manifest guidance when the error is the backend's not-found sentinel", async () => {
    (api.manifestDiff as Mock).mockRejectedValue(new Error("no izba.yml found in workspace"));
    render(<ManifestTab name="web" running={true} />);

    expect(
      await screen.findByText("No izba.yml found in this sandbox's workspace."),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        "Create an izba.yml in the workspace to manage this sandbox declaratively — the manifest describes image, resources, ports, volumes and firewall policy. Run 'izba export <name>' or use Export here after making changes in the app.",
      ),
    ).toBeInTheDocument();
  });

  it("enables Export (no disabled hint) in the missing-manifest state — the bootstrap case", async () => {
    (api.manifestDiff as Mock).mockRejectedValue(new Error("no izba.yml found in workspace"));
    render(<ManifestTab name="web" running={true} />);

    await screen.findByText("No izba.yml found in this sandbox's workspace.");
    const exportBtn = screen.getByRole("button", { name: /^export to izba\.yml$/i });
    // The empty-state guidance says "use Export here" — the button must not be
    // permanently disabled just because manifest_diff errored on the missing
    // file (the backend's export never reads an existing izba.yml).
    expect(exportBtn).not.toBeDisabled();
    expect(exportBtn).not.toHaveAttribute("title");
  });

  it("bootstrap-exports from the missing-manifest state: calls manifestExport, shows the confirmation, and lands in_sync", async () => {
    (api.manifestDiff as Mock).mockRejectedValue(new Error("no izba.yml found in workspace"));
    (api.manifestExport as Mock).mockResolvedValue("/ws/izba.yml");
    render(<ManifestTab name="web" running={true} />);

    await screen.findByText("No izba.yml found in this sandbox's workspace.");
    const exportBtn = screen.getByRole("button", { name: /^export to izba\.yml$/i });
    expect(exportBtn).not.toBeDisabled();

    // The post-export refetch finds the just-written file in sync — mirrors
    // the real backend, where export writes izba.yml from managed truth.
    (api.manifestDiff as Mock).mockResolvedValue({ state: "in_sync", deltas: [] });
    fireEvent.click(exportBtn);
    await waitFor(() => expect(api.manifestExport).toHaveBeenCalledWith("web"));

    expect(await screen.findByText("Exported to /ws/izba.yml")).toBeInTheDocument();
    expect(
      await screen.findByText("In sync — izba.yml and managed settings match."),
    ).toBeInTheDocument();
    // The missing-manifest guidance is gone — the file exists now.
    expect(
      screen.queryByText("No izba.yml found in this sandbox's workspace."),
    ).not.toBeInTheDocument();
  });

  it("shows the raw message in the error area for a non-manifest error", async () => {
    (api.manifestDiff as Mock).mockRejectedValue(new Error("daemon unreachable"));
    render(<ManifestTab name="web" running={true} />);

    expect(await screen.findByText("daemon unreachable")).toBeInTheDocument();
    expect(
      screen.queryByText("No izba.yml found in this sandbox's workspace."),
    ).not.toBeInTheDocument();
  });

  it("shows a parse-error message mentioning izba.yml in the raw error area, not the missing-manifest guidance", async () => {
    // A corrupt izba.yml surfaces as "parsing izba.yml: ..." from
    // Manifest::load_str — it mentions "izba.yml" but is NOT the backend's
    // stable "no izba.yml found in workspace" not-found sentinel, so it must
    // render honestly instead of being mislabeled as a missing file.
    (api.manifestDiff as Mock).mockRejectedValue(
      new Error("parsing izba.yml: invalid type: string, expected struct SandboxSpec"),
    );
    render(<ManifestTab name="web" running={true} />);

    expect(
      await screen.findByText("parsing izba.yml: invalid type: string, expected struct SandboxSpec"),
    ).toBeInTheDocument();
    expect(
      screen.queryByText("No izba.yml found in this sandbox's workspace."),
    ).not.toBeInTheDocument();
  });

  it("Refresh re-calls manifestDiff", async () => {
    (api.manifestDiff as Mock).mockResolvedValue({ state: "in_sync", deltas: [] });
    render(<ManifestTab name="web" running={true} />);
    await screen.findByText("In sync — izba.yml and managed settings match.");

    fireEvent.click(screen.getByRole("button", { name: /^refresh$/i }));
    await waitFor(() => expect(api.manifestDiff).toHaveBeenCalledTimes(2));
  });
});

/** #241: the drift banner is a recommendation, and the recommendation has to
 *  know WHICH WAY the drift cuts. `compute_diff` is `diff(managed, repo)`, so
 *  `weakens_egress` on a pending delta means "promoting izba.yml would weaken
 *  egress" — the banner must not then advise Promote while a red
 *  "⚠ weakens egress" marker sits on the delta row below it. */
describe("ManifestTab drift banner direction", () => {
  async function renderDiff(state: string, deltas: unknown[]) {
    (api.manifestDiff as Mock).mockResolvedValue({ state, deltas });
    render(<ManifestTab name="web" running={true} />);
  }

  it("in_sync renders the unchanged in-sync copy", async () => {
    await renderDiff("in_sync", []);
    expect(await screen.findByText(IN_SYNC_BANNER)).toBeInTheDocument();
  });

  it("repo_ahead with a non-weakening egress delta keeps the unchanged Promote copy", async () => {
    await renderDiff("repo_ahead", [STRENGTHENING_EGRESS_DELTA]);
    expect(await screen.findByText(REPO_AHEAD_BANNER)).toBeInTheDocument();
  });

  it("managed_ahead with a non-weakening delta keeps the unchanged Export copy", async () => {
    await renderDiff("managed_ahead", [BENIGN_DELTA]);
    expect(await screen.findByText(MANAGED_AHEAD_BANNER)).toBeInTheDocument();
  });

  it("diverged with a non-weakening delta keeps the unchanged both-changed copy", async () => {
    await renderDiff("diverged", [BENIGN_DELTA]);
    expect(await screen.findByText(DIVERGED_BANNER)).toBeInTheDocument();
  });

  it("repo_ahead + weakening stops recommending Promote and keeps the delta marker", async () => {
    await renderDiff("repo_ahead", [WEAKENING_DELTA]);

    expect(await screen.findByText(REPO_AHEAD_WEAKENS_BANNER)).toBeInTheDocument();
    // The defect: the banner used to advise the exact action the marker on
    // the row below warns about.
    expect(screen.queryByText(REPO_AHEAD_BANNER)).not.toBeInTheDocument();
    expect(screen.getByText("⚠ weakens egress")).toBeInTheDocument();
  });

  it("managed_ahead + weakening recommends Export", async () => {
    await renderDiff("managed_ahead", [WEAKENING_DELTA]);
    expect(await screen.findByText(MANAGED_AHEAD_WEAKENS_BANNER)).toBeInTheDocument();
    expect(screen.queryByText(MANAGED_AHEAD_BANNER)).not.toBeInTheDocument();
  });

  it("diverged + weakening leads with Export and qualifies Promote", async () => {
    await renderDiff("diverged", [WEAKENING_DELTA]);
    expect(await screen.findByText(DIVERGED_WEAKENS_BANNER)).toBeInTheDocument();
    expect(screen.queryByText(DIVERGED_BANNER)).not.toBeInTheDocument();
  });

  it("diverged with no deltas says there is nothing to apply and points at Export", async () => {
    // Both sides moved since the last reconcile but landed on the same
    // values: the generic "Promote applies izba.yml" copy claimed a
    // divergence with an empty delta table under it and no next step.
    await renderDiff("diverged", []);
    expect(await screen.findByText(DIVERGED_NO_DELTAS_BANNER)).toBeInTheDocument();
    expect(screen.queryByText(DIVERGED_BANNER)).not.toBeInTheDocument();
    expect(
      screen.getByText("No field changes between izba.yml and managed settings."),
    ).toBeInTheDocument();
  });

  it("a NON-egress repo_ahead drift is unaffected (no regression)", async () => {
    await renderDiff("repo_ahead", [BENIGN_DELTA]);
    expect(await screen.findByText(REPO_AHEAD_BANNER)).toBeInTheDocument();
    expect(screen.queryByText(REPO_AHEAD_WEAKENS_BANNER)).not.toBeInTheDocument();
    expect(screen.queryByText("⚠ weakens egress")).not.toBeInTheDocument();
  });

  it("styles the weakening repo_ahead banner destructively, agreeing with the row marker", async () => {
    await renderDiff("repo_ahead", [WEAKENING_DELTA]);
    const banner = await screen.findByText(REPO_AHEAD_WEAKENS_BANNER);
    expect(banner.className).toContain("border-destructive");
    expect(banner.className).toContain("text-destructive");
    // The neutral primary tint would read as "this is fine, go ahead".
    expect(banner.className).not.toContain("border-primary");
  });

  it("keeps the neutral styling for a non-weakening repo_ahead drift", async () => {
    await renderDiff("repo_ahead", [BENIGN_DELTA]);
    const banner = await screen.findByText(REPO_AHEAD_BANNER);
    expect(banner.className).toContain("border-primary");
    expect(banner.className).not.toContain("destructive");
  });
});

describe("ManifestTab promote dialog", () => {
  it("opens listing the delta fields for a repo_ahead diff", async () => {
    (api.manifestDiff as Mock).mockResolvedValue({
      state: "repo_ahead",
      deltas: [{ field: "cpus", from: "2", to: "4", class: "restart", weakens_egress: false }],
    });
    render(<ManifestTab name="web" running={true} />);
    await screen.findByText("izba.yml has changes not yet applied. Review below, then Promote.");

    fireEvent.click(screen.getByRole("button", { name: /^promote…$/i }));

    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText("Promote izba.yml changes")).toBeInTheDocument();
    expect(
      within(dialog).getByText("The following changes will be applied to 'web':"),
    ).toBeInTheDocument();
    expect(within(dialog).getByText("cpus")).toBeInTheDocument();
    // Same shared DeltaTable/ValueDiff as the tab body, so the confirm
    // dialog names its sides too.
    expect(within(dialog).getByText("From (managed)")).toBeInTheDocument();
    expect(within(dialog).getByText("To (izba.yml)")).toBeInTheDocument();
  });

  it("keeps the Promote confirm disabled until the weakens-egress ack is checked", async () => {
    (api.manifestDiff as Mock).mockResolvedValue({
      state: "repo_ahead",
      deltas: [
        {
          field: "policy.egress.enforce",
          from: "true",
          to: "false",
          class: "live",
          weakens_egress: true,
        },
      ],
    });
    render(<ManifestTab name="web" running={true} />);
    // This diff's only delta weakens egress, so the loaded-barrier is the
    // direction-aware banner, not the generic repo_ahead one (#241).
    await screen.findByText(REPO_AHEAD_WEAKENS_BANNER);
    fireEvent.click(screen.getByRole("button", { name: /^promote…$/i }));

    const dialog = screen.getByRole("dialog");
    const confirm = within(dialog).getByRole("button", { name: /^promote$/i });
    expect(confirm).toBeDisabled();

    fireEvent.click(
      within(dialog).getByRole("checkbox", {
        name: "I understand this weakens the egress firewall",
      }),
    );
    expect(confirm).not.toBeDisabled();
  });

  it("confirms, calls manifestPromote(name, false), renders the outcome, and refetches the diff", async () => {
    (api.manifestDiff as Mock).mockResolvedValue({
      state: "repo_ahead",
      deltas: [{ field: "cpus", from: "2", to: "4", class: "live", weakens_egress: false }],
    });
    (api.manifestPromote as Mock).mockResolvedValue(
      promoteView({
        applied: [{ field: "cpus", from: "2", to: "4", class: "live", weakens_egress: false }],
        warnings: ["port 8080 already published"],
      }),
    );
    render(<ManifestTab name="web" running={true} />);
    await screen.findByText("izba.yml has changes not yet applied. Review below, then Promote.");
    fireEvent.click(screen.getByRole("button", { name: /^promote…$/i }));

    const dialog = screen.getByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: /^promote$/i }));

    await waitFor(() => expect(api.manifestPromote).toHaveBeenCalledWith("web", false));
    expect(await within(dialog).findByText("Promoted 1 change(s).")).toBeInTheDocument();
    expect(within(dialog).getByText("port 8080 already published")).toBeInTheDocument();
    await waitFor(() => expect(api.manifestDiff).toHaveBeenCalledTimes(2));
  });

  it("maps the core's --reset-scratch expert warning to friendly copy, leaving other warnings passed through", async () => {
    (api.manifestDiff as Mock).mockResolvedValue({
      state: "repo_ahead",
      deltas: [{ field: "image", from: "alpine:3.20", to: "alpine:3.21", class: "image", weakens_egress: false }],
    });
    (api.manifestPromote as Mock).mockResolvedValue(
      promoteView({
        applied: [{ field: "image", from: "alpine:3.20", to: "alpine:3.21", class: "image", weakens_egress: false }],
        restarted: true,
        warnings: [
          "WARNING: --reset-scratch=false keeps the rw overlay built on the PREVIOUS image. " +
            "Packages installed (e.g. apt-get) against the old base may have missing libs / " +
            "wrong ABI on the new image and can render the guest UNBOOTABLE. Proceed only if " +
            "you understand overlay semantics.",
          "port 8080 already published",
        ],
      }),
    );
    render(<ManifestTab name="web" running={false} />);
    await screen.findByText("izba.yml has changes not yet applied. Review below, then Promote.");
    fireEvent.click(screen.getByRole("button", { name: /^promote…$/i }));

    const dialog = screen.getByRole("dialog");
    fireEvent.click(
      within(dialog).getByRole("checkbox", {
        name: "Start the sandbox to apply the image change (the scratch disk is kept, not reset)",
      }),
    );
    fireEvent.click(within(dialog).getByRole("button", { name: /^promote$/i }));

    expect(
      await within(dialog).findByText(
        "Note: the scratch disk was kept. If the sandbox misbehaves on the new image, recreate it or reset from the CLI.",
      ),
    ).toBeInTheDocument();
    expect(within(dialog).queryByText(/--reset-scratch/)).not.toBeInTheDocument();
    // Unmapped warnings still pass through verbatim.
    expect(within(dialog).getByText("port 8080 already published")).toBeInTheDocument();
  });

  it("shows a restart checkbox for a restart-class delta while running and promotes with restart=true", async () => {
    (api.manifestDiff as Mock).mockResolvedValue({
      state: "repo_ahead",
      deltas: [{ field: "mem_mb", from: "2048", to: "4096", class: "restart", weakens_egress: false }],
    });
    (api.manifestPromote as Mock).mockResolvedValue(promoteView({ needs_restart: true }));
    render(<ManifestTab name="web" running={true} />);
    await screen.findByText("izba.yml has changes not yet applied. Review below, then Promote.");
    fireEvent.click(screen.getByRole("button", { name: /^promote…$/i }));

    const dialog = screen.getByRole("dialog");
    fireEvent.click(
      within(dialog).getByRole("checkbox", { name: "Restart now to apply restart-class changes" }),
    );
    fireEvent.click(within(dialog).getByRole("button", { name: /^promote$/i }));

    await waitFor(() => expect(api.manifestPromote).toHaveBeenCalledWith("web", true));
  });

  it("does not show the restart checkbox when the sandbox is stopped and only restart-class (non-image) deltas are pending, and promotes with restart=false", async () => {
    (api.manifestDiff as Mock).mockResolvedValue({
      state: "repo_ahead",
      deltas: [{ field: "mem_mb", from: "2048", to: "4096", class: "restart", weakens_egress: false }],
    });
    (api.manifestPromote as Mock).mockResolvedValue(promoteView({ needs_restart: true, stopped: true }));
    render(<ManifestTab name="web" running={false} />);
    await screen.findByText("izba.yml has changes not yet applied. Review below, then Promote.");
    fireEvent.click(screen.getByRole("button", { name: /^promote…$/i }));

    const dialog = screen.getByRole("dialog");
    expect(
      within(dialog).queryByRole("checkbox", { name: "Restart now to apply restart-class changes" }),
    ).not.toBeInTheDocument();
    expect(within(dialog).queryByRole("checkbox")).not.toBeInTheDocument();

    fireEvent.click(within(dialog).getByRole("button", { name: /^promote$/i }));
    await waitFor(() => expect(api.manifestPromote).toHaveBeenCalledWith("web", false));
  });

  it("shows the stopped-image checkbox for a STOPPED sandbox with an image delta, disables confirm until checked, and promotes with restart=true", async () => {
    (api.manifestDiff as Mock).mockResolvedValue({
      state: "repo_ahead",
      deltas: [{ field: "image", from: "alpine:3.20", to: "alpine:3.21", class: "image", weakens_egress: false }],
    });
    (api.manifestPromote as Mock).mockResolvedValue(
      promoteView({
        applied: [{ field: "image", from: "alpine:3.20", to: "alpine:3.21", class: "image", weakens_egress: false }],
        restarted: true,
        stopped: true,
      }),
    );
    render(<ManifestTab name="web" running={false} />);
    await screen.findByText("izba.yml has changes not yet applied. Review below, then Promote.");
    fireEvent.click(screen.getByRole("button", { name: /^promote…$/i }));

    const dialog = screen.getByRole("dialog");
    // The generic "apply on next start" note must not appear alongside an
    // image delta — it would contradict the gate, which needs the checkbox
    // ticked now rather than promising automatic application later.
    expect(
      within(dialog).queryByText("Changes that need a restart apply on the next start."),
    ).not.toBeInTheDocument();

    const checkbox = within(dialog).getByRole("checkbox", {
      name: "Start the sandbox to apply the image change (the scratch disk is kept, not reset)",
    });
    const confirm = within(dialog).getByRole("button", { name: /^promote$/i });
    expect(confirm).toBeDisabled();

    fireEvent.click(checkbox);
    expect(confirm).not.toBeDisabled();

    fireEvent.click(confirm);
    await waitFor(() => expect(api.manifestPromote).toHaveBeenCalledWith("web", true));
    // The pre-promote state was "stopped", but the promote actually started
    // it (restarted:true) — the outcome text must say so, not repeat the
    // stale "Sandbox is stopped" line.
    expect(await within(dialog).findByText("Sandbox was started to apply the change.")).toBeInTheDocument();
    expect(within(dialog).queryByText("Sandbox is stopped — changes apply on next start.")).not.toBeInTheDocument();
  });

  it("shows the running restart-checkbox label (unchanged) for an image delta while running, and gates confirm on it", async () => {
    (api.manifestDiff as Mock).mockResolvedValue({
      state: "repo_ahead",
      deltas: [{ field: "image", from: "alpine:3.20", to: "alpine:3.21", class: "image", weakens_egress: false }],
    });
    render(<ManifestTab name="web" running={true} />);
    await screen.findByText("izba.yml has changes not yet applied. Review below, then Promote.");
    fireEvent.click(screen.getByRole("button", { name: /^promote…$/i }));

    const dialog = screen.getByRole("dialog");
    const checkbox = within(dialog).getByRole("checkbox", {
      name: "Restart now to apply restart-class changes",
    });
    const confirm = within(dialog).getByRole("button", { name: /^promote$/i });
    expect(confirm).toBeDisabled();

    fireEvent.click(checkbox);
    expect(confirm).not.toBeDisabled();

    fireEvent.click(confirm);
    await waitFor(() => expect(api.manifestPromote).toHaveBeenCalledWith("web", true));
  });

  it("maps an image-change-requires-restart promote rejection to its GUI copy (belt and braces)", async () => {
    (api.manifestDiff as Mock).mockResolvedValue({
      state: "repo_ahead",
      deltas: [{ field: "image", from: "alpine:3.20", to: "alpine:3.21", class: "image", weakens_egress: false }],
    });
    (api.manifestPromote as Mock).mockRejectedValue(
      new Error(
        "image change requires --restart (the rw scratch overlay must be reset on the new base; " +
          "pass --restart, optionally with --reset-scratch=false to keep the old overlay at your own risk)",
      ),
    );
    render(<ManifestTab name="web" running={false} />);
    await screen.findByText("izba.yml has changes not yet applied. Review below, then Promote.");
    fireEvent.click(screen.getByRole("button", { name: /^promote…$/i }));

    const dialog = screen.getByRole("dialog");
    fireEvent.click(
      within(dialog).getByRole("checkbox", {
        name: "Start the sandbox to apply the image change (the scratch disk is kept, not reset)",
      }),
    );
    fireEvent.click(within(dialog).getByRole("button", { name: /^promote$/i }));

    expect(
      await within(dialog).findByText(
        "This image change needs the checkbox above ticked before Promote can continue.",
      ),
    ).toBeInTheDocument();
    expect(within(dialog).queryByText(/--restart/)).not.toBeInTheDocument();
    expect(within(dialog).queryByText(/--reset-scratch/)).not.toBeInTheDocument();
  });

  it("maps a stale-token promote rejection to its copy", async () => {
    (api.manifestDiff as Mock).mockResolvedValue({
      state: "repo_ahead",
      deltas: [{ field: "cpus", from: "2", to: "4", class: "live", weakens_egress: false }],
    });
    (api.manifestPromote as Mock).mockRejectedValue(new Error("izba.yml changed since last review"));
    render(<ManifestTab name="web" running={true} />);
    await screen.findByText("izba.yml has changes not yet applied. Review below, then Promote.");
    fireEvent.click(screen.getByRole("button", { name: /^promote…$/i }));

    const dialog = screen.getByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: /^promote$/i }));

    expect(
      await within(dialog).findByText(
        "izba.yml changed since you viewed this diff. Refresh and review again.",
      ),
    ).toBeInTheDocument();
  });

  it("maps a never-reviewed promote rejection to its copy", async () => {
    (api.manifestDiff as Mock).mockResolvedValue({
      state: "repo_ahead",
      deltas: [{ field: "cpus", from: "2", to: "4", class: "live", weakens_egress: false }],
    });
    (api.manifestPromote as Mock).mockRejectedValue(new Error("no reviewed diff on file"));
    render(<ManifestTab name="web" running={true} />);
    await screen.findByText("izba.yml has changes not yet applied. Review below, then Promote.");
    fireEvent.click(screen.getByRole("button", { name: /^promote…$/i }));

    const dialog = screen.getByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: /^promote$/i }));

    expect(
      await within(dialog).findByText(
        "Review the diff first — open this tab's latest state, then Promote.",
      ),
    ).toBeInTheDocument();
  });
});
