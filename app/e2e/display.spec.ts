import { test, expect } from "./fixtures";
import { vncEnabledScenario } from "./mock/scenarios";

test.describe("display tab", () => {
  test("stopped sandbox, vnc off: enable desktop records the call, no restart banner", async ({
    page,
    mock,
  }) => {
    // "db" (postgres:16) is stopped and vnc-off in the default scenario.
    await page.getByText("postgres:16").click();
    await page.getByRole("tab", { name: "Display" }).click();

    await expect(
      page.getByText("Run a full Linux desktop in this sandbox, streamed to your browser."),
    ).toBeVisible();

    await page.getByRole("button", { name: "Enable desktop" }).click();
    await expect.poll(() => mock.calls()).toContain("vnc_set:db:true");

    // The mock only flags vnc_restart_required for a RUNNING sandbox, so a
    // stopped one falls through to "not-running" — proves the reload landed
    // and confirms the restart banner never appears for a stopped sandbox.
    await expect(
      page.getByText("The sandbox is stopped — start it to reach the desktop."),
    ).toBeVisible();
    await expect(
      page.getByText("Restart the sandbox to apply the desktop change."),
    ).not.toBeVisible();
  });

  test("running sandbox, vnc off: enable desktop shows the restart-required banner", async ({
    page,
    mock,
  }) => {
    // "web" (ubuntu:24.04) is running and vnc-off in the default scenario.
    await page.getByText("ubuntu:24.04").click();
    await page.getByRole("tab", { name: "Display" }).click();

    await page.getByRole("button", { name: "Enable desktop" }).click();
    await expect.poll(() => mock.calls()).toContain("vnc_set:web:true");

    // Detail.tsx's own action toolbar also has a "Restart" button for the
    // whole sandbox, so scope to the Display tab's banner (its immediate
    // parent) to avoid a strict-mode ambiguity between the two.
    const banner = page
      .getByText("Restart the sandbox to apply the desktop change.")
      .locator("..");
    await expect(banner).toBeVisible();
    await expect(banner.getByRole("button", { name: "Restart" })).toBeVisible();
  });

  test.describe("live desktop", () => {
    test.use({ scenario: vncEnabledScenario() });

    test("running sandbox with a live desktop embeds the proxy URL, never the credentialed one", async ({
      page,
    }) => {
      await page.getByText("ubuntu:24.04").click();
      await page.getByRole("tab", { name: "Display" }).click();

      const iframe = page.locator("iframe[title='Sandbox desktop']");
      await expect(iframe).toBeVisible();
      // The embed src is the credential-less loopback proxy the mock's
      // vnc_proxy_start returns — NOT the scenario's password-bearing
      // vnc_url. A regression that wired the raw vnc_url into the iframe
      // would fail this exact assertion. The #show_control_bar=1 fragment
      // keeps the KasmVNC client out of its iframe-embedded mode (which
      // never paints the initial keyframe — black desktop, working input).
      await expect(iframe).toHaveAttribute("src", "http://127.0.0.1:1/#show_control_bar=1");

      await expect(page.getByRole("button", { name: "Open in browser" })).toBeVisible();
      await expect(page.getByRole("button", { name: "Copy URL" })).toBeVisible();

      // CREDENTIAL DISCIPLINE: the scenario's vnc_url is
      // "http://izba:pw@127.0.0.1:4444/" — its "izba:pw" userinfo must never
      // land anywhere in the rendered page (text, attributes, or otherwise).
      // Checking full page.content() (not just visible text) means a leak
      // into e.g. an iframe src or a title attribute would trip this too.
      const content = await page.content();
      expect(content).not.toContain("izba:pw");
    });
  });
});
