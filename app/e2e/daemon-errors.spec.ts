import { test, expect } from "./fixtures";
import { defaultScenario } from "./mock/scenarios";

test.describe("daemon error states", () => {
  test.describe("daemon unreachable", () => {
    test.use({
      scenario: {
        sandboxes: [],
        daemonAbsent: true,
        failList: true,
        failStatus: true,
        errorMessage: "daemon unreachable",
      },
    });
    test("shows daemon unreachable in top bar", async ({ page }) => {
      await expect(page.getByText(/daemon unreachable/i)).toBeVisible();
    });
  });

  test.describe("version mismatch", () => {
    const mismatchScenario = (() => {
      const s = defaultScenario();
      s.version!.mismatch = true;
      return s;
    })();

    test.use({ scenario: mismatchScenario });

    test("shows a mismatch warning in the About dialog", async ({ page }) => {
      // The mismatch flag only surfaces in the About dialog (About.tsx, not TopBar).
      await page.getByRole("button", { name: /about/i }).click();
      await expect(page.getByRole("dialog", { name: /about/i })).toBeVisible();
      await expect(page.getByText(/app and daemon builds differ/i)).toBeVisible();
    });
  });
});
