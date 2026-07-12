import { test, expect } from "./fixtures";

// ManifestTab reads window.__MOCK_MANIFEST__ live on every manifest_diff/
// manifest_export/manifest_promote call (see e2e/mock/tauri-mock.js), so a
// spec can flip it mid-test and trigger a Refresh to pick up the new state.
type MockManifestOverride = {
  diff?: unknown;
  export?: unknown;
  promote?: unknown;
  promoteError?: string;
};

function setMockManifest(override: MockManifestOverride) {
  (window as unknown as { __MOCK_MANIFEST__: MockManifestOverride }).__MOCK_MANIFEST__ = override;
}

// A repo_ahead diff with a single image-class delta — the same shape the
// "stopped sandbox, image change" gate exercises (RESTART_CHECKBOX_LABEL_STOPPED_IMAGE
// / RESTART_CHECKBOX_LABEL in ManifestTab.tsx): Promote stays disabled until the
// restart/start checkbox is ticked, then confirming calls manifestPromote(name, true).
const IMAGE_DRIFT_DIFF = {
  state: "repo_ahead",
  deltas: [
    {
      field: "image",
      from: "ubuntu:22.04",
      to: "ubuntu:24.04",
      class: "image",
      weakens_egress: false,
    },
  ],
};

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

  test("promote start-failure renders the friendly committed-but-not-started copy", async ({
    page,
  }) => {
    // Arrange the same image-drift mock state the existing promote spec
    // above uses, but make manifest_promote reject with the core's
    // start-failure message (izba-core/src/manifest/promote.rs) instead of
    // resolving — exercising the GUI's mapping of that raw CLI-speak error.
    await page.evaluate(setMockManifest, {
      diff: IMAGE_DRIFT_DIFF,
      promoteError:
        "failed to start sandbox after promote (config already committed); run `izba start web` to retry: vmm exploded",
    });
    await page.getByText("ubuntu:24.04").click();
    await page.getByRole("tab", { name: "Manifest" }).click();

    await page.getByRole("button", { name: "Promote…" }).click();
    const dialog = page.getByRole("dialog");
    await expect(dialog.getByText("Promote izba.yml changes")).toBeVisible();

    const confirm = dialog.getByRole("button", { name: "Promote", exact: true });
    await expect(confirm).toBeDisabled();

    // The image-class delta gate needs the restart/start checkbox ticked
    // before Promote is clickable at all (RESTART_CHECKBOX_LABEL).
    await dialog
      .getByRole("checkbox", { name: "Restart now to apply restart-class changes" })
      .click();
    await expect(confirm).toBeEnabled();
    await confirm.click();

    await expect(
      dialog.getByText(
        "Promoted, but the sandbox failed to start on the new configuration. Use Start on the sandbox to retry.",
      ),
    ).toBeVisible();
  });

  test("promote stop-failure renders the friendly committed-but-not-restarted copy", async ({
    page,
  }) => {
    // Same image-drift mock state, but the core's stop-failure message
    // instead: the config committed but the pre-restart Stop leg failed.
    await page.evaluate(setMockManifest, {
      diff: IMAGE_DRIFT_DIFF,
      promoteError:
        "failed to stop sandbox for restart (the promote itself is committed; restart manually to apply): vmm exploded",
    });
    await page.getByText("ubuntu:24.04").click();
    await page.getByRole("tab", { name: "Manifest" }).click();

    await page.getByRole("button", { name: "Promote…" }).click();
    const dialog = page.getByRole("dialog");
    await expect(dialog.getByText("Promote izba.yml changes")).toBeVisible();

    await dialog
      .getByRole("checkbox", { name: "Restart now to apply restart-class changes" })
      .click();
    await dialog.getByRole("button", { name: "Promote", exact: true }).click();

    await expect(
      dialog.getByText(
        "Promoted, but the sandbox could not be stopped to apply restart-class changes. Stop and Start it manually.",
      ),
    ).toBeVisible();
  });
});
