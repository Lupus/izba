import { test, expect } from "./fixtures";

test.describe("about", () => {
  test("opens the About dialog and shows version and git sha", async ({ page }) => {
    await page.getByRole("button", { name: "About" }).click();
    const dialog = page.getByRole("dialog", { name: /about izba/i });
    await expect(dialog).toBeVisible();
    // defaultScenario buildInfo: pkg_version "0.3.1", git_sha "abc1234"
    // About.tsx renders short(b) = "0.3.1 (abc1234)" for each component (app/core/daemon = 3 rows)
    await expect(dialog.getByText(/0\.3\.1/).first()).toBeVisible();
    await expect(dialog.getByText(/abc1234/).first()).toBeVisible();
  });
});
