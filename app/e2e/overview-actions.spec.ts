import { test, expect } from "./fixtures";
import { defaultScenario } from "./mock/scenarios";

test.describe("overview actions", () => {
  test("stop on running sandbox shows confirm dialog then calls stop", async ({ page, mock }) => {
    // Select running sandbox by its unique image
    await page.getByText("ubuntu:24.04").click();
    // Detail section is a <section>; scope button clicks to it
    const detail = page.locator("section");
    // Stop button sets pending, opens ConfirmDialog
    await detail.getByRole("button", { name: "Stop", exact: true }).click();
    // ConfirmDialog appears with title "Stop web?"
    const dialog = page.getByRole("dialog", { name: /stop web/i });
    await expect(dialog).toBeVisible();
    // Confirm the stop
    await dialog.getByRole("button", { name: "Stop" }).click();
    await expect.poll(() => mock.calls()).toContain("stop:web");
  });

  test("start on stopped sandbox calls start", async ({ page, mock }) => {
    // Select stopped sandbox by its unique image
    await page.getByText("postgres:16").click();
    const detail = page.locator("section");
    await detail.getByRole("button", { name: "Start", exact: true }).click();
    await expect.poll(() => mock.calls()).toContain("start:db");
  });

  test("remove asks for confirmation then calls remove", async ({ page, mock }) => {
    await page.getByText("postgres:16").click();
    await page.getByRole("button", { name: "Remove" }).click();
    // ConfirmDialog has title "Remove db?"
    const dialog = page.getByRole("dialog", { name: /remove db/i });
    await expect(dialog).toBeVisible();
    await dialog.getByRole("button", { name: "Remove" }).click();
    await expect.poll(() => mock.calls()).toEqual(
      expect.arrayContaining([expect.stringMatching(/^remove:db:/)]),
    );
  });

  test.describe("degraded state", () => {
    test.use({
      scenario: {
        ...defaultScenario(),
        sandboxes: [
          {
            name: "web",
            image: "ubuntu:24.04",
            state: { kind: "degraded", reason: "vm exited unexpectedly" },
          },
        ],
        daemonStatus: { version: "0.3.1", pid: 4242, uptime_ms: 1000, sandbox_count: 1 },
      },
    });

    test("shows the degraded reason in the detail pane", async ({ page }) => {
      await page.getByText("ubuntu:24.04").click();
      await expect(page.getByText(/vm exited unexpectedly/)).toBeVisible();
    });
  });
});
