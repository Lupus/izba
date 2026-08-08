import { render, screen } from "@testing-library/react";
import { describe, it, expect, vi, afterEach } from "vitest";
import { runningStats, stoppedStats } from "./fixtures";

import { ProcessesCard } from "../../components/overview/ProcessesCard";

describe("ProcessesCard", () => {
  it("renders the guest mini-top with pid, name, CPU% and memory", () => {
    render(<ProcessesCard stats={runningStats()} />);
    expect(screen.getByRole("columnheader", { name: "PID" })).toBeInTheDocument();
    expect(screen.getByText("42")).toBeInTheDocument();
    expect(screen.getByText("node")).toBeInTheDocument();
    expect(screen.getByText("21.0")).toBeInTheDocument();
    expect(screen.getByText("64.0 MiB")).toBeInTheDocument();
  });

  it("labels the table as guest-reported and footers the total count", () => {
    render(<ProcessesCard stats={runningStats()} />);
    expect(screen.getByText(/guest-reported/)).toBeInTheDocument();
    expect(screen.getByText("61 total")).toBeInTheDocument();
  });

  it("never grows past ten rows", () => {
    const s = runningStats();
    const many = Array.from({ length: 15 }, (_, i) => ({
      pid: 100 + i,
      comm: `p${i}`,
      state: "S",
      cpu_permille: 10,
      rss_kb: 1024,
    }));
    render(<ProcessesCard stats={runningStats({ guest: { ...s.guest!, processes: many } })} />);
    expect(screen.getAllByRole("row")).toHaveLength(11); // header + 10
  });

  it("says the guest is not responding when it could not be reached", () => {
    render(<ProcessesCard stats={runningStats({ guest: null })} />);
    expect(screen.getByText("guest not responding")).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("says not running for a stopped sandbox", () => {
    render(<ProcessesCard stats={stoppedStats()} />);
    expect(screen.getByText("not running")).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  describe("with a hostile guest reporting duplicate pids", () => {
    afterEach(() => {
      vi.restoreAllMocks();
    });

    it("does not warn React about a duplicate/missing \"key\" prop", () => {
      // The guest is untrusted (see the file-header comment): it can report
      // the same pid twice. A key derived from pid alone would collide and
      // trip React's duplicate-key warning; the row index must be folded in.
      const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
      const s = runningStats();
      const dup = [
        { pid: 7, comm: "a", state: "S", cpu_permille: 1, rss_kb: 1 },
        { pid: 7, comm: "b", state: "S", cpu_permille: 2, rss_kb: 2 },
      ];
      render(<ProcessesCard stats={runningStats({ guest: { ...s.guest!, processes: dup } })} />);
      const keyWarnings = errorSpy.mock.calls.filter((args) =>
        String(args[0]).includes("key"),
      );
      expect(keyWarnings).toHaveLength(0);
      // Both duplicate-pid rows still render distinctly.
      expect(screen.getByText("a")).toBeInTheDocument();
      expect(screen.getByText("b")).toBeInTheDocument();
    });
  });
});
