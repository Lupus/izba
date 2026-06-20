import { test, expect } from "./fixtures";
import { defaultScenario } from "./mock/scenarios";

const logsScenario = defaultScenario();
logsScenario.logs = "boot ok\nready on tty\n";

test.describe("logs", () => {
  test.use({ scenario: logsScenario });

  test("shows console output in the Logs tab", async ({ page, mock }) => {
    // Select web (running) sandbox
    await page.getByText("ubuntu:24.04").click();
    // Click the Logs tab
    await page.getByRole("tab", { name: "Logs" }).click();
    // Should call read_logs for the selected sandbox
    await expect.poll(() => mock.calls()).toContain("read_logs:web");
    // The log text should render in the pre element
    await expect(page.getByTestId("log-output")).toContainText("ready on tty");
  });
});
