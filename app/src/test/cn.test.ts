import { describe, it, expect } from "vitest";
import { cn } from "@/lib/utils";

describe("cn", () => {
  it("merges class names", () => {
    expect(cn("a", "b")).toBe("a b");
  });
  it("dedupes conflicting tailwind utilities (last wins)", () => {
    expect(cn("px-2", "px-4")).toBe("px-4");
  });
  it("drops falsy values", () => {
    // `off` is boolean-typed (not a literal) so the falsy operand isn't a
    // constant binary expression — keeps the intent (cn drops falsy values)
    // without tripping no-constant-binary-expression.
    const off: boolean = false;
    expect(cn("a", off && "b", undefined, "c")).toBe("a c");
  });
});
