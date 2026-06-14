import { render, screen, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { About } from "../components/About";
import type { BuildInfo } from "../lib/types";

const build = (sha: string): BuildInfo => ({
  pkg_version: "0.1.0",
  git_describe: `v0.1.0-g${sha.slice(0, 7)}`,
  git_sha: sha,
  commit_date: "2026-06-14",
  build_timestamp: "2026-06-14T10:00:00Z",
  rustc: "1.96.0",
  target: "x86_64-unknown-linux-gnu",
  profile: "release",
});

vi.mock("../lib/ipc", () => ({
  api: { versionInfo: vi.fn() },
}));

describe("About", () => {
  beforeEach(() => vi.clearAllMocks());

  it("renders app/core/daemon builds and warns on mismatch", async () => {
    const { api } = await import("../lib/ipc");
    (api.versionInfo as ReturnType<typeof vi.fn>).mockResolvedValue({
      app: build("aaaaaaa0000"),
      core: build("aaaaaaa0000"),
      daemon: build("bbbbbbb1111"),
      proto: 1,
      mismatch: true,
    });
    render(<About onClose={() => {}} />);
    await waitFor(() => expect(screen.getByText("App")).toBeInTheDocument());
    expect(screen.getByText("Core")).toBeInTheDocument();
    expect(screen.getByText("Daemon")).toBeInTheDocument();
    expect(screen.getByText(/builds differ/i)).toBeInTheDocument();
    // Short sha rendering: first 7 chars of the daemon sha.
    expect(screen.getByText(/bbbbbbb/)).toBeInTheDocument();
  });

  it("shows 'not running' when no daemon and no mismatch warning", async () => {
    const { api } = await import("../lib/ipc");
    (api.versionInfo as ReturnType<typeof vi.fn>).mockResolvedValue({
      app: build("aaaaaaa0000"),
      core: build("aaaaaaa0000"),
      daemon: null,
      proto: 0,
      mismatch: false,
    });
    render(<About onClose={() => {}} />);
    await waitFor(() => expect(screen.getByText("not running")).toBeInTheDocument());
    expect(screen.queryByText(/builds differ/i)).not.toBeInTheDocument();
  });
});
