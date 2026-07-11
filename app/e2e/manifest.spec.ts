import { test, expect } from "./fixtures";

// ManifestTab reads window.__MOCK_MANIFEST__ live on every manifest_diff/
// manifest_export/manifest_promote call (see e2e/mock/tauri-mock.js), so a
// spec can flip it mid-test and trigger a Refresh to pick up the new state.
type MockManifestOverride = {
  diff?: unknown;
  export?: unknown;
  promote?: unknown;
};

function setMockManifest(override: MockManifestOverride) {
  (window as unknown as { __MOCK_MANIFEST__: MockManifestOverride }).__MOCK_MANIFEST__ = override;
}

test.describe("manifest tab", () => {
  test("repo_ahead promote flow, then managed_ahead export flow", async ({ page }) => {
    await page.getByText("ubuntu:24.04").click();
    await page.getByRole("tab", { name: "Manifest" }).click();

    // Default mock diff is repo_ahead with a single weakens_egress delta.
    await expect(
      page.getByText("izba.yml has changes not yet applied. Review below, then Promote."),
    ).toBeVisible();
    await expect(page.getByText("⚠ weakens egress")).toBeVisible();

    await page.getByRole("button", { name: "Promote…" }).click();
    const dialog = page.getByRole("dialog");
    await expect(dialog.getByText("Promote izba.yml changes")).toBeVisible();

    const confirm = dialog.getByRole("button", { name: "Promote", exact: true });
    await expect(confirm).toBeDisabled();

    await dialog
      .getByRole("checkbox", { name: "I understand this weakens the egress firewall" })
      .click();
    await expect(confirm).toBeEnabled();
    await confirm.click();

    await expect(dialog.getByText("Promoted 1 change(s).")).toBeVisible();
    // The dialog also carries a Radix "X" close button whose accessible name
    // is also "Close" — target the footer button precisely by its variant.
    await dialog.getByRole("button", { name: "Close", exact: true }).last().click();
    await expect(dialog).toBeHidden();

    // Switch the mocked diff to managed_ahead and pick it up via Refresh.
    await page.evaluate(setMockManifest, { diff: { state: "managed_ahead", deltas: [] } });
    await page.getByRole("button", { name: "Refresh" }).click();
    await expect(
      page.getByText("Live settings have drifted from izba.yml. Export to capture them."),
    ).toBeVisible();

    // Real Export writes izba.yml to match managed truth, so the next
    // manifest_diff reads in_sync; mirror that in the mock so this test
    // exercises the post-export refetch, not a stale managed_ahead re-render.
    await page.evaluate(setMockManifest, { diff: { state: "in_sync", deltas: [] } });
    await page.getByRole("button", { name: "Export to izba.yml" }).click();

    // The export confirmation must survive the refetch it triggers, and the
    // banner must flip to in_sync — not stay on the stale managed_ahead
    // reading (the bug this journey guards against).
    await expect(page.getByText("Exported to /ws/izba.yml")).toBeVisible();
    await expect(
      page.getByText("In sync — izba.yml and managed settings match."),
    ).toBeVisible();
  });
});
