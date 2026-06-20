import { test as base, expect } from "@playwright/test";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { defaultScenario, type Scenario } from "./mock/scenarios";
import { MockHandle } from "./helpers";

const HERE = dirname(fileURLToPath(import.meta.url));
const MOCK_PATH = resolve(HERE, "mock/tauri-mock.js");

type Fixtures = {
  /** Override per file/test with test.use({ scenario: {...} }). */
  scenario: Scenario;
  /** Installed mock; navigates to "/" before the test body runs. */
  mock: MockHandle;
};

export const test = base.extend<Fixtures>({
  scenario: [defaultScenario(), { option: true }],
  // `auto: true` so the mock is installed and the page navigated even for tests
  // that take only `{ page }` and never destructure `mock`.
  mock: [
    async ({ page, scenario }, use) => {
      await page.addInitScript((s) => {
        (window as unknown as { __IZBA_SCENARIO__: Scenario }).__IZBA_SCENARIO__ = s;
      }, scenario);
      await page.addInitScript({ path: MOCK_PATH });
      await page.goto("/");
      await use(new MockHandle(page));
    },
    { auto: true },
  ],
});

export { expect };
