import { test, expect } from "./fixtures";
import { defaultScenario } from "./mock/scenarios";

async function openDialog(page: import("@playwright/test").Page) {
  await page.getByRole("button", { name: "New sandbox" }).click();
  return page.getByRole("dialog", { name: "New sandbox" });
}

test.describe("new sandbox", () => {
  test("submits create with the entered options", async ({ page, mock }) => {
    const dlg = await openDialog(page);
    await dlg.getByLabel("Name").fill("api");
    // Workspace input has aria-label "Workspace"
    await dlg.getByLabel("Workspace").fill("/home/u/api");
    await dlg.getByLabel("Image").fill("node:22");
    await dlg.getByRole("button", { name: "Create" }).click();
    await expect.poll(() => mock.calls()).toContain("create:api");
    const opts = await mock.lastCreate();
    expect(opts).toMatchObject({ name: "api", workspace: "/home/u/api", image: "node:22" });
  });

  test.describe("create with progress", () => {
    test.use({
      scenario: {
        ...defaultScenario(),
        createDeferred: true,
      },
    });

    test("streams create-progress messages then closes dialog on resolve", async ({
      page,
      mock,
    }) => {
      const dlg = await openDialog(page);
      await dlg.getByLabel("Name").fill("api");
      await dlg.getByLabel("Workspace").fill("/home/u/api");
      await dlg.getByRole("button", { name: "Create" }).click();
      // Wait for create to be called (deferred, so dialog stays open)
      await expect.poll(() => mock.calls()).toContain("create:api");
      await mock.pushCreateProgress("pulling image");
      await mock.pushCreateProgress("booting");
      await expect(dlg.getByText("pulling image")).toBeVisible();
      await expect(dlg.getByText("booting")).toBeVisible();
      await mock.resolveCreate("api");
      // Dialog closes after create resolves
      await expect(page.getByRole("dialog", { name: "New sandbox" })).toHaveCount(0);
    });
  });

  test.describe("create error", () => {
    test.use({
      scenario: {
        ...defaultScenario(),
        createError: "image not found",
      },
    });

    test("surfaces the create error in the dialog", async ({ page }) => {
      const dlg = await openDialog(page);
      await dlg.getByLabel("Name").fill("api");
      await dlg.getByLabel("Workspace").fill("/home/u/api");
      await dlg.getByRole("button", { name: "Create" }).click();
      await expect(dlg.getByText(/image not found/)).toBeVisible();
    });
  });
});
