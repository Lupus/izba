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

  it("enables Export on managed_ahead and reports the exported path after a click", async () => {
    (api.manifestDiff as Mock).mockResolvedValue({ state: "managed_ahead", deltas: [] });
    (api.manifestExport as Mock).mockResolvedValue("/ws/izba.yml");
    render(<ManifestTab name="web" running={true} />);

    const exportBtn = await screen.findByRole("button", { name: /^export to izba\.yml$/i });
    expect(exportBtn).not.toBeDisabled();
    // Promote stays disabled — managed_ahead has nothing repo-side to promote.
    expect(screen.getByRole("button", { name: /^promote…$/i })).toBeDisabled();

    fireEvent.click(exportBtn);
    await waitFor(() => expect(api.manifestExport).toHaveBeenCalledWith("web"));
    expect(await screen.findByText("Exported to /ws/izba.yml")).toBeInTheDocument();
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

  it("does not show the restart checkbox when the sandbox is stopped", async () => {
    (api.manifestDiff as Mock).mockResolvedValue({
      state: "repo_ahead",
      deltas: [{ field: "mem_mb", from: "2048", to: "4096", class: "restart", weakens_egress: false }],
    });
    render(<ManifestTab name="web" running={false} />);
    await screen.findByText("izba.yml has changes not yet applied. Review below, then Promote.");
    fireEvent.click(screen.getByRole("button", { name: /^promote…$/i }));

    const dialog = screen.getByRole("dialog");
    expect(
      within(dialog).queryByRole("checkbox", { name: "Restart now to apply restart-class changes" }),
    ).not.toBeInTheDocument();
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
