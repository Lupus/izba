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
    // Assert on the app's own stable container (ShellViewer's data-testid) rather
    // than xterm's private `.xterm-rows` class, which a minor xterm release could
    // rename without a semver-breaking change and make this pass vacuously.
    await expect(page.getByTestId("shell-host")).toContainText("hello-from-guest");
  });

  test("typing into the terminal sends shell_write", async ({ page, mock }) => {
    const id = await openShellTab(page, mock);
    // Focus xterm's keyboard-capture textarea. Scope by element type within our
    // stable shell-host container instead of xterm's private
    // `.xterm-helper-textarea` class: the input element stays a <textarea> across
    // xterm versions even if the class name changes, so this can't silently no-op.
    await page.getByTestId("shell-host").locator("textarea").focus();
    await page.keyboard.type("ls");
    await expect.poll(() => mock.calls()).toEqual(
      expect.arrayContaining([expect.stringMatching(new RegExp(`^shell_write:${id}:`))]),
    );
  });

  test("a shell-exit event marks the session as exited", async ({ page, mock }) => {
    const id = await openShellTab(page, mock);
    await mock.fireShellExit(id);
    // ShellPanel appends " (exited)" to the shell tab button
    await expect(page.getByRole("tab", { name: /exited/i })).toBeVisible();
  });
});
