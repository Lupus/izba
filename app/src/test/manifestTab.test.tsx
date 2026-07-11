import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach, type Mock } from "vitest";
import { ManifestTab } from "../components/ManifestTab";
import { api } from "../lib/ipc";

vi.mock("../lib/ipc", () => ({
  api: {
    manifestDiff: vi.fn(),
    manifestExport: vi.fn(),
  },
}));

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

  it("shows missing-manifest guidance when the error mentions izba.yml", async () => {
    (api.manifestDiff as Mock).mockRejectedValue(new Error("reading /ws/izba.yml: No such file"));
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

  it("Refresh re-calls manifestDiff", async () => {
    (api.manifestDiff as Mock).mockResolvedValue({ state: "in_sync", deltas: [] });
    render(<ManifestTab name="web" running={true} />);
    await screen.findByText("In sync — izba.yml and managed settings match.");

    fireEvent.click(screen.getByRole("button", { name: /^refresh$/i }));
    await waitFor(() => expect(api.manifestDiff).toHaveBeenCalledTimes(2));
  });
});
