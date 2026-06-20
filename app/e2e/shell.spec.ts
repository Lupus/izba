import { test, expect } from "./fixtures";

/** Navigate to the Shell tab for the "web" (running) sandbox and return the minted session id. */
async function openShellTab(
  page: import("@playwright/test").Page,
  mock: import("./helpers").MockHandle,
): Promise<string> {
  await page.getByText("ubuntu:24.04").click();
  await page.getByRole("tab", { name: "Shell" }).click();
  // The store auto-opens one shell; poll until shell_open:web:<id> appears.
  let openCall: string | undefined;
  await expect
    .poll(async () => {
      const calls = await mock.calls();
      openCall = calls.find((c) => c.startsWith("shell_open:web:"));
      return openCall;
    })
    .not.toBeUndefined();
  // openCall is e.g. "shell_open:web:sh-0"; split on ":" taking 3rd segment
  return openCall!.split(":")[2];
}

test.describe("shell", () => {
  test("opens a session and renders streamed output in xterm", async ({ page, mock }) => {
    const id = await openShellTab(page, mock);
    await mock.pushShellOutput(id, "hello-from-guest\r\n");
    // xterm DOM renderer puts text into .xterm-rows
    await expect(page.locator(".xterm-rows")).toContainText("hello-from-guest");
  });

  test("typing into the terminal sends shell_write", async ({ page, mock }) => {
    const id = await openShellTab(page, mock);
    // Focus the xterm hidden textarea that captures keyboard input
    await page.locator(".xterm-helper-textarea").focus();
    await page.keyboard.type("ls");
    await expect.poll(() => mock.calls()).toEqual(
      expect.arrayContaining([expect.stringMatching(new RegExp(`^shell_write:${id}:`))]),
    );
  });

  test("a shell-exit event marks the session as exited", async ({ page, mock }) => {
    const id = await openShellTab(page, mock);
    await mock.fireShellExit(id);
    // ShellPanel appends " (exited)" to the tab label on exit
    await expect(page.getByText(/exited/i)).toBeVisible();
  });
});
