import { test, expect } from "./fixtures";
import { defaultScenario } from "./mock/scenarios";

async function openSave(page: import("@playwright/test").Page) {
  await page.getByRole("button", { name: "Save archive" }).click();
  return page.getByRole("dialog", { name: "Save sandboxes" });
}

async function openLoad(page: import("@playwright/test").Page) {
  await page.getByRole("button", { name: "Load archive" }).click();
  return page.getByRole("dialog", { name: "Load sandboxes" });
}

test.describe("save archive", () => {
  test("saves the chosen stopped sandbox with its workspace", async ({ page, mock }) => {
    const dlg = await openSave(page);
    await dlg.getByRole("checkbox", { name: "Save db" }).click();
    await dlg.getByRole("checkbox", { name: "Include workspace folders" }).click();
    await dlg.getByLabel("Archive file").fill("/backups/db.izba");
    await dlg.getByRole("button", { name: "Save", exact: true }).click();
    await expect.poll(() => mock.calls()).toContain("save_archive:db:/backups/db.izba:true:false");
    expect(await mock.lastSave()).toEqual({
      names: ["db"],
      out: "/backups/db.izba",
      with_workspace: true,
      stop: false,
      overwrite: false,
    });
    await expect(dlg.getByText("Saved 1 sandbox to")).toBeVisible();
    await expect(dlg.getByText("/backups/db.izba")).toBeVisible();
    await expect(dlg.getByText("1.5 GiB archive")).toBeVisible();
    await dlg.getByRole("button", { name: "Done" }).click();
    await expect(page.getByRole("dialog", { name: "Save sandboxes" })).toHaveCount(0);
  });

  test("a running sandbox is only saved once the user agrees to stop it", async ({
    page,
    mock,
  }) => {
    const dlg = await openSave(page);
    await dlg.getByRole("checkbox", { name: "Save web" }).click();
    await dlg.getByLabel("Archive file").fill("/backups/web.izba");
    const save = dlg.getByRole("button", { name: "Save", exact: true });
    await expect(save).toBeDisabled();
    await expect(dlg.getByText(/web is running/)).toBeVisible();
    await dlg.getByRole("checkbox", { name: "Stop running sandboxes first" }).click();
    await save.click();
    await expect.poll(() => mock.calls()).toContain("save_archive:web:/backups/web.izba:false:true");
  });

  test.describe("slow save", () => {
    test.use({ scenario: { ...defaultScenario(), saveDeferred: true } });

    test("streams progress while the archive is written", async ({ page, mock }) => {
      const dlg = await openSave(page);
      await dlg.getByRole("checkbox", { name: "Save db" }).click();
      await dlg.getByLabel("Archive file").fill("/backups/db.izba");
      await dlg.getByRole("button", { name: "Save", exact: true }).click();
      await expect.poll(() => mock.calls()).toContain("save_archive:db:/backups/db.izba:false:false");
      await expect(dlg.getByRole("button", { name: "Saving…" })).toBeDisabled();
      await mock.pushSaveProgress("archiving 'db'");
      await expect(dlg.getByText("archiving 'db'")).toBeVisible();
      await mock.resolveSave();
      await expect(dlg.getByText("Saved 1 sandbox to")).toBeVisible();
    });
  });

  test.describe("save error", () => {
    test.use({
      scenario: { ...defaultScenario(), saveError: "/backups/db.izba already exists" },
    });

    test("surfaces the failure in the dialog", async ({ page }) => {
      const dlg = await openSave(page);
      await dlg.getByRole("checkbox", { name: "Save db" }).click();
      await dlg.getByLabel("Archive file").fill("/backups/db.izba");
      await dlg.getByRole("button", { name: "Save", exact: true }).click();
      await expect(dlg.getByText("/backups/db.izba already exists")).toBeVisible();
    });
  });
});

test.describe("load archive", () => {
  test("reads the archive, then loads it under a new name", async ({ page, mock }) => {
    const dlg = await openLoad(page);
    const load = dlg.getByRole("button", { name: "Load", exact: true });
    await expect(load).toBeDisabled();
    await dlg.getByLabel("Archive file").fill("/in/api.izba");
    await dlg.getByRole("button", { name: "Read archive" }).click();
    await expect.poll(() => mock.calls()).toContain("archive_inspect:/in/api.izba");
    await expect(dlg.getByRole("checkbox", { name: "Load api" })).toBeChecked();
    await expect(dlg.getByText("workspace included")).toBeVisible();
    await dlg.getByLabel("Load as").fill("api2");
    await dlg.getByLabel("Workspace folder", { exact: true }).fill("/home/u/api2");
    await load.click();
    await expect
      .poll(() => mock.calls())
      .toContain("load_archive:/in/api.izba:api:api2:/home/u/api2:");
    expect(await mock.lastLoad()).toEqual({
      archive: "/in/api.izba",
      select: ["api"],
      rename: "api2",
      workspace: "/home/u/api2",
      workspace_root: null,
    });
    await expect(dlg.getByText("Loaded 1 sandbox:")).toBeVisible();
    await expect(dlg.getByText("arrive stopped")).toBeVisible();
    await dlg.getByRole("button", { name: "Done" }).click();
    await expect(page.getByRole("dialog", { name: "Load sandboxes" })).toHaveCount(0);
    // The loaded sandbox joins the rail.
    await expect(page.getByRole("button", { name: /api2/ })).toBeVisible();
  });

  test.describe("name collision", () => {
    test.use({
      scenario: {
        ...defaultScenario(),
        archive: {
          izba_version: "0.1.0",
          source_os: "windows",
          created_unix_ms: 1700000000000,
          sandboxes: [
            { name: "web", workspace_bundled: false, source_workspace: "C:\\src\\web", locked: true },
            { name: "api", workspace_bundled: true, source_workspace: "C:\\src\\api", locked: false },
          ],
        },
        loadRedo: ["re-run: izba lockdown web2"],
      },
    });

    test("a taken name blocks the load until it is resolved", async ({ page, mock }) => {
      const dlg = await openLoad(page);
      await dlg.getByLabel("Archive file").fill("/in/two.izba");
      await dlg.getByRole("button", { name: "Read archive" }).click();
      const load = dlg.getByRole("button", { name: "Load", exact: true });
      await expect(dlg.getByText(/web already exists/)).toBeVisible();
      await expect(load).toBeDisabled();
      await expect(dlg.getByText(/was locked down on the source machine/)).toBeVisible();
      await dlg.getByRole("checkbox", { name: "Load api" }).click();
      await dlg.getByLabel("Load as").fill("web2");
      await expect(load).toBeEnabled();
      await load.click();
      await expect.poll(() => mock.calls()).toContain("load_archive:/in/two.izba:web:web2::");
      await expect(dlg.getByText("re-run: izba lockdown web2")).toBeVisible();
    });
  });

  test.describe("unreadable archive", () => {
    test.use({ scenario: { ...defaultScenario(), archiveError: "not an izba archive" } });

    test("says why and keeps Load disabled", async ({ page }) => {
      const dlg = await openLoad(page);
      await dlg.getByLabel("Archive file").fill("/in/notes.txt");
      await dlg.getByRole("button", { name: "Read archive" }).click();
      await expect(dlg.getByText("not an izba archive")).toBeVisible();
      await expect(dlg.getByRole("button", { name: "Load", exact: true })).toBeDisabled();
    });
  });

  test.describe("load error", () => {
    test.use({ scenario: { ...defaultScenario(), loadError: "not enough free space" } });

    test("surfaces the failure in the dialog", async ({ page }) => {
      const dlg = await openLoad(page);
      await dlg.getByLabel("Archive file").fill("/in/api.izba");
      await dlg.getByRole("button", { name: "Read archive" }).click();
      await dlg.getByRole("button", { name: "Load", exact: true }).click();
      await expect(dlg.getByText("not enough free space")).toBeVisible();
    });
  });
});
