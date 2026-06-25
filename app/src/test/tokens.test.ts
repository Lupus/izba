import { describe, it, expect } from "vitest";
import config from "../../tailwind.config";

describe("tailwind tokens", () => {
  const colors = (config.theme?.extend?.colors ?? {}) as Record<string, unknown>;
  it.each([
    "primary", "secondary", "destructive", "muted", "accent",
    "background", "foreground", "card", "popover", "border", "input", "ring",
    "success", "sidebar", "muted-foreground-2",
  ])("exposes the %s token", (name) => {
    expect(colors[name]).toBeDefined();
  });
  it("primary references the CSS variable, not a hex literal", () => {
    expect(JSON.stringify(colors.primary)).toContain("var(--primary)");
  });
});
