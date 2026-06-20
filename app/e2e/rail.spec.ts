import { test, expect } from "./fixtures";

test.describe("rail", () => {
  test("selecting db sandbox shows its detail with postgres:16", async ({ page }) => {
    // Use image string (unique) not sandbox name to avoid "db" matching "New sandbox"
    await page.getByText("postgres:16").click();
    // Detail pane shows the image
    await expect(page.getByText("postgres:16")).toHaveCount(2); // rail item + detail
  });

  test("the New sandbox button opens the create dialog", async ({ page }) => {
    await page.getByRole("button", { name: "New sandbox" }).click();
    await expect(page.getByRole("dialog", { name: "New sandbox" })).toBeVisible();
  });
});
