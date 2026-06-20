import type { Page } from "@playwright/test";
import type { Scenario, CreateOpts } from "./mock/scenarios";

/** Node-side proxy over the in-page window.__IZBA_MOCK__ control surface. */
export class MockHandle {
  constructor(private page: Page) {}

  calls(): Promise<string[]> {
    return this.page.evaluate(() => (window as unknown as IzbaWindow).__IZBA_MOCK__.calls());
  }
  lastCreate(): Promise<CreateOpts | undefined> {
    return this.page.evaluate(() => (window as unknown as IzbaWindow).__IZBA_MOCK__.lastCreate());
  }
  pushCreateProgress(msg: string): Promise<void> {
    return this.page.evaluate(
      (m) => (window as unknown as IzbaWindow).__IZBA_MOCK__.pushCreateProgress(m),
      msg,
    );
  }
  pushShellOutput(id: string, text: string): Promise<void> {
    return this.page.evaluate(
      ([i, t]) => (window as unknown as IzbaWindow).__IZBA_MOCK__.pushShellOutput(i, t),
      [id, text] as const,
    );
  }
  fireShellExit(id: string): Promise<void> {
    return this.page.evaluate(
      (i) => (window as unknown as IzbaWindow).__IZBA_MOCK__.fireShellExit(i),
      id,
    );
  }
  resolveCreate(name: string): Promise<void> {
    return this.page.evaluate(
      (n) => (window as unknown as IzbaWindow).__IZBA_MOCK__.resolveCreate(n),
      name,
    );
  }
  rejectCreate(msg: string): Promise<void> {
    return this.page.evaluate(
      (m) => (window as unknown as IzbaWindow).__IZBA_MOCK__.rejectCreate(m),
      msg,
    );
  }
  setScenario(partial: Partial<Scenario>): Promise<void> {
    return this.page.evaluate(
      (p) => (window as unknown as IzbaWindow).__IZBA_MOCK__.setScenario(p),
      partial,
    );
  }
}

/** Shape of the in-page control surface installed by mock/tauri-mock.js. */
interface IzbaWindow {
  __IZBA_MOCK__: {
    calls(): string[];
    lastCreate(): CreateOpts | undefined;
    pushCreateProgress(msg: string): void;
    pushShellOutput(id: string, text: string): void;
    fireShellExit(id: string): void;
    resolveCreate(name: string): void;
    rejectCreate(msg: string): void;
    setScenario(partial: Partial<Scenario>): void;
  };
}
