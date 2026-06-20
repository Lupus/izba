import { test, expect } from "./fixtures";
import { defaultScenario } from "./mock/scenarios";

// PolicyView requires a git field (used by PolicyEditor via p.git.map(toGitRow))
const policyScenario = defaultScenario();
policyScenario.policy = {
  web: {
    enforcing: true,
    allow: ["github.com", { host: "api.x.com", ports: [443] }],
    git: [],
  },
};

test.describe("policy editor", () => {
  test.use({ scenario: policyScenario });

  test("shows the loaded policy and enforcing state", async ({ page, mock }) => {
    await page.getByText("ubuntu:24.04").click();
    await page.getByRole("tab", { name: "Policy" }).click();
    await expect.poll(() => mock.calls()).toContain("policy_show:web");
    // Both allowed hosts should appear in the editor inputs
    await expect(page.locator('input[value="github.com"]')).toBeVisible();
    await expect(page.locator('input[value="api.x.com"]')).toBeVisible();
    // The enforce toggle shows "Firewall on" (enforcing: true)
    await expect(page.getByText(/Firewall on/i)).toBeVisible();
  });

  test("allow host from netlog calls policy_allow", async ({ page, mock }) => {
    // Switch to Netlog tab — policy_allow is the per-row action button in NetlogView
    // Set up a netlog entry so there's an Allow button to click (enforcing policy needed)
    // Use setScenario to add a netlog entry with enforcing + a host not yet allowed
    await mock.setScenario({
      netlog: [
        {
          host: "example.com",
          dest_ip: "93.184.216.34",
          port: 80,
          tier: "l7",
          verdict: "deny",
          allow_count: 0,
          deny_count: 1,
          first_seen_ms: 1000,
          last_seen_ms: 2000,
          last_method: "GET",
          last_path: "/",
        },
      ],
    });
    await page.getByText("ubuntu:24.04").click();
    await page.getByRole("tab", { name: "Netlog" }).click();
    await expect.poll(() => mock.calls()).toContain("read_netlog:web");
    // In enforcing mode, each row shows an Allow button for non-allowed hosts
    await expect(page.getByRole("button", { name: /Allow example\.com/i })).toBeVisible();
    await page.getByRole("button", { name: /Allow example\.com/i }).click();
    await expect.poll(() => mock.calls()).toContain("policy_allow:web:example.com:80");
  });
});
