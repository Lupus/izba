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
});
