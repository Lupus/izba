import { test, expect } from "./fixtures";
import { defaultScenario } from "./mock/scenarios";
import type { EndpointSummary } from "../src/lib/types";

const netlogEntries: EndpointSummary[] = [
  {
    host: "github.com",
    dest_ip: "140.82.112.3",
    port: 443,
    tier: "l7",
    verdict: "allow",
    allow_count: 5,
    deny_count: 0,
    first_seen_ms: 1000,
    last_seen_ms: 2000,
    last_method: "GET",
    last_path: "/",
  },
  {
    host: null,
    dest_ip: "10.0.0.9",
    port: 22,
    tier: "l3",
    verdict: "deny",
    allow_count: 0,
    deny_count: 3,
    first_seen_ms: 1000,
    last_seen_ms: 1500,
    last_method: null,
    last_path: null,
  },
];

const netlogScenario = defaultScenario();
netlogScenario.netlog = netlogEntries;
// Provide a policy with git field so NetlogView's allowKeys + policy?.git ?? [] is safe
netlogScenario.policy = { web: { enforcing: false, allow: [], git: [] } };

test.describe("netlog", () => {
  test.use({ scenario: netlogScenario });

  test("renders endpoint summaries in the Netlog tab", async ({ page, mock }) => {
    await page.getByText("ubuntu:24.04").click();
    await page.getByRole("tab", { name: "Netlog" }).click();
    await expect.poll(() => mock.calls()).toContain("read_netlog:web");
    // Host column shows the resolved hostname
    await expect(page.getByText("github.com")).toBeVisible();
    // Raw-IP row shows the dest_ip
    await expect(page.getByText("10.0.0.9")).toBeVisible();
    // Port column
    await expect(page.getByText("443")).toBeVisible();
    await expect(page.getByText("22")).toBeVisible();
    // Tier column
    await expect(page.getByText("l7")).toBeVisible();
    await expect(page.getByText("l3")).toBeVisible();
  });

  test("the review dialog is a frozen snapshot while live traffic keeps arriving, driven by keyboard", async ({ page, mock }) => {
    await page.getByText("ubuntu:24.04").click();
    await page.getByRole("tab", { name: "Netlog" }).click();
    await expect.poll(() => mock.calls()).toContain("read_netlog:web");
    await page.getByRole("button", { name: "Review observed traffic" }).click();
    const dialog = page.getByRole("dialog");
    await expect(dialog).toBeVisible();

    // Snapshot at open: github.com:443 selectable, the raw IP listed but disabled,
    // nothing ticked, submit disabled at 0.
    const github = dialog.getByRole("checkbox", { name: "github.com:443" });
    await expect(github).toBeVisible();
    await expect(github).not.toBeChecked();
    await expect(dialog.getByRole("checkbox", { name: "10.0.0.9:22" })).toBeDisabled();
    const add = dialog.getByRole("button", { name: /^Add \d+ selected to allow-list$/ });
    await expect(add).toHaveText("Add 0 selected to allow-list");
    await expect(add).toBeDisabled();

    // Live traffic arrives underneath the open dialog: a brand-new endpoint,
    // and the existing ones re-timestamped so the backend order would flip.
    await mock.setScenario({
      netlog: [
        {
          host: "pypi.org",
          dest_ip: "151.101.0.223",
          port: 443,
          tier: "l7",
          verdict: "allow",
          allow_count: 1,
          deny_count: 0,
          first_seen_ms: 3000,
          last_seen_ms: 3000,
          last_method: "GET",
          last_path: "/simple/",
        },
        ...netlogEntries.map((e) => ({ ...e, last_seen_ms: e.last_seen_ms + 5000 })),
      ],
    });
    // The poll delivered it (the notice proves the data reached the dialog)…
    await expect(dialog.getByRole("status")).toHaveText(
      "1 new endpoint(s) observed since this review — refresh to include them.",
      { timeout: 10_000 },
    );
    // …yet the reviewed list is unchanged: same membership, same order.
    await expect(dialog.getByRole("checkbox", { name: "pypi.org:443" })).toHaveCount(0);
    await expect(dialog.getByRole("checkbox")).toHaveCount(2); // still exactly two rows
    await expect(dialog.getByRole("checkbox").first()).toHaveAccessibleName("github.com:443");

    // Keyboard only from here: tick github.com via Space, refresh via Enter.
    await github.focus();
    await page.keyboard.press("Space");
    await expect(github).toBeChecked();
    await expect(add).toHaveText("Add 1 selected to allow-list");
    await dialog.getByRole("button", { name: "Refresh" }).focus();
    await page.keyboard.press("Enter");
    // Sorted by key: github < pypi < raw-ip. Existing tick kept, new row untouched.
    await expect(dialog.getByRole("checkbox")).toHaveCount(3);
    await expect(dialog.getByRole("checkbox").nth(0)).toHaveAccessibleName("github.com:443");
    await expect(dialog.getByRole("checkbox").nth(1)).toHaveAccessibleName("pypi.org:443");
    await expect(dialog.getByRole("checkbox").nth(2)).toHaveAccessibleName("10.0.0.9:22");
    await expect(github).toBeChecked();
    await expect(dialog.getByRole("checkbox", { name: "pypi.org:443" })).not.toBeChecked();
    await expect(dialog.getByRole("status")).toHaveText("");
    await expect(add).toHaveText("Add 1 selected to allow-list");

    await add.focus();
    await page.keyboard.press("Enter");
    await expect.poll(() => mock.calls()).toContain("policy_add_endpoints:web:1:false");
    await expect(dialog).toHaveCount(0);
  });
});
