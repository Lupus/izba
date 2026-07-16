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

describe("ManifestTab", () => {
  it("fetches on mount and renders the repo_ahead banner + a weakening delta row", async () => {
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

    expect(
      await screen.findByText("izba.yml has changes not yet applied. Review below, then Promote."),
    ).toBeInTheDocument();
    expect(screen.getByText("policy.egress.enforce")).toBeInTheDocument();
    expect(screen.getByText("live")).toBeInTheDocument();
    expect(screen.getByText("⚠ weakens egress")).toBeInTheDocument();
    expect(api.manifestDiff).toHaveBeenCalledWith("web");
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
    (api.manifestDiff as Mock).mockResolvedValue({ state: "diverged", deltas: [] });
    render(<ManifestTab name="web" running={true} />);

    expect(
      await screen.findByText(
        "Both izba.yml and managed settings changed. Promote applies izba.yml; Export overwrites it.",
      ),
    ).toBeInTheDocument();
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
    await screen.findByText("izba.yml has changes not yet applied. Review below, then Promote.");
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
