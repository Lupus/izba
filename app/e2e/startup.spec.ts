import { test, expect } from "./fixtures";

test.describe("startup & polling", () => {
  test("renders the seeded sandbox list", async ({ page }) => {
    // Image strings are unique; sandbox names like "db" collide with "New sandbox".
    await expect(page.getByText("ubuntu:24.04")).toBeVisible();
    await expect(page.getByText("postgres:16")).toBeVisible();
    await expect(page.getByText(/Sandboxes · 2/)).toBeVisible();
  });

  test("shows daemon running + version in the top bar", async ({ page }) => {
    await expect(page.getByText(/daemon running/)).toBeVisible();
    await expect(page.getByText(/v0\.3\.1/)).toBeVisible();
  });

  test("polling reflects scenario changes", async ({ page, mock }) => {
    await expect(page.getByText("postgres:16")).toBeVisible();
    await mock.setScenario({
      sandboxes: [{ name: "web", image: "ubuntu:24.04", state: { kind: "running" } }],
      daemonStatus: { version: "0.3.1", pid: 4242, uptime_ms: 1000, sandbox_count: 1 },
    });
    // usePolling refreshes every 2s; Playwright assertions auto-wait.
    await expect(page.getByText("postgres:16")).toHaveCount(0);
    await expect(page.getByText(/Sandboxes · 1/)).toBeVisible();
  });
});
