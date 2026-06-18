import { describe, it, expect } from "vitest";
import { git_access_for, globMatch, git_repo_from_row } from "../lib/git";
import type { GitRule } from "../lib/types";

describe("globMatch", () => {
  it("* matches one segment only", () => {
    expect(globMatch("gitlab.com/vendor/*", "gitlab.com/vendor/lib")).toBe(true);
    expect(globMatch("gitlab.com/vendor/*", "gitlab.com/vendor/sub/lib")).toBe(false);
    expect(globMatch("github.com/o/a", "github.com/o/a")).toBe(true);
    expect(globMatch("github.com/o/a", "github.com/o/b")).toBe(false);
  });
});

describe("git_access_for", () => {
  const rules: GitRule[] = [
    { repo: "github.com/o/a", access: "read" },
    { host: "bitbucket.org", access: "read-write" },
    { repo: "gitlab.com/vendor/*" }, // access omitted → read
  ];
  it("exact repo → its access", () => expect(git_access_for("github.com/o/a", rules)).toBe("read"));
  it("host scope → its access", () => expect(git_access_for("bitbucket.org/x/y", rules)).toBe("read-write"));
  it("owner glob, access defaulted read", () => expect(git_access_for("gitlab.com/vendor/lib", rules)).toBe("read"));
  it("no match → null", () => expect(git_access_for("github.com/o/z", rules)).toBeNull());
});

describe("git_repo_from_row", () => {
  it("strips suffix + .git, prefixes host", () =>
    expect(git_repo_from_row("github.com", "/o/a.git/git-receive-pack")).toBe("github.com/o/a"));
});
