import { test, expect } from "./fixtures";
import { lockdownScenario } from "./mock/scenarios";

test.describe("lock-down row", () => {
  test.describe("supported host", () => {
    test.use({ scenario: lockdownScenario() });

    test("lock down then unlock", async ({ page, mock }) => {
      await page.getByText("ubuntu:24.04").click();
      await expect(page.getByText("unlocked", { exact: true })).toBeVisible();

      await page.getByRole("button", { name: "Lock down" }).click();
      await expect.poll(() => mock.calls()).toContain("lockdown:web");
      await expect(page.getByText("locked · izba-sb-web · network blocked")).toBeVisible();
      await expect(page.getByText("restart to apply")).toBeVisible();

      await page.getByRole("button", { name: "Unlock", exact: true }).click();
      await page.getByRole("button", { name: "Unlock sandbox" }).click();
      await expect.poll(() => mock.calls()).toContain("unlock:web");
      await expect(page.getByText("unlocked", { exact: true })).toBeVisible();
    });
  });

  test.describe("declined UAC", () => {
    test.use({ scenario: { ...lockdownScenario(), lockdownOutcome: "cancelled" } });

    test("a cancel is quiet and changes nothing", async ({ page }) => {
      await page.getByText("ubuntu:24.04").click();
      await page.getByRole("button", { name: "Lock down" }).click();
      await expect(page.getByText("cancelled — nothing changed")).toBeVisible();
      await expect(page.getByText("unlocked", { exact: true })).toBeVisible();
    });
  });

  test("no row when the host has no lock-down", async ({ page }) => {
    await page.getByText("ubuntu:24.04").click();
    await expect(page.getByText("confinement")).toBeVisible();
    await expect(page.getByText("lock-down")).toHaveCount(0);
  });
});
