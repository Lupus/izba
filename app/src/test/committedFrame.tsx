/** Test harness for THE frame a passive effect cannot protect.
 *
 *  React commits the render carrying a new prop first; whatever a `useEffect`
 *  does about that prop lands in a LATER render. In between there is a real,
 *  painted, interactive frame whose event handlers still close over the
 *  PREVIOUS props' state. RTL's `rerender` hides the whole thing: it wraps the
 *  update in `act`, which renders, commits, flushes effects and re-renders
 *  before it returns — so a component that repairs itself in an effect looks
 *  correct to every test written that way, while a user gets the frame.
 *
 *  `inFrame` stops inside that frame. `flushSync` renders and commits
 *  synchronously; the state a name-change effect queues in response has not
 *  been rendered when the callback runs, so the DOM the callback queries and
 *  the handlers it fires are exactly the ones the user is handed.
 *
 *  Interactions inside the frame are dispatched with `rawClick` rather than
 *  RTL's `fireEvent`: `fireEvent` is wrapped in `act` (which defeats the point
 *  of standing outside it), and a bubbling MouseEvent is what the browser
 *  hands React's root listener anyway.
 *
 *  Assert on what an interaction in the frame makes the component DO — which
 *  daemon call, with which arguments — never on markup, which can be right for
 *  the wrong reason. */
import { act } from "@testing-library/react";
import { flushSync } from "react-dom";
import { createRoot, type Root } from "react-dom/client";
import type { ReactElement } from "react";

interface ActEnv {
  IS_REACT_ACT_ENVIRONMENT?: boolean;
}

export interface FrameHarness {
  /** The mount point; query it with `within(container)`. */
  container: HTMLElement;
  /** Commit `ui` and let React finish: effects, pending promises, re-renders. */
  settle: (ui: ReactElement) => Promise<void>;
  /** Commit `ui` and run `fn` in that frame, before any repair re-renders. */
  inFrame: (ui: ReactElement, fn: () => void | Promise<void>) => Promise<void>;
  unmount: () => Promise<void>;
}

export function frameHarness(): FrameHarness {
  const container = document.createElement("div");
  document.body.appendChild(container);
  const root: Root = createRoot(container);
  const env = globalThis as ActEnv;

  return {
    container,
    async settle(ui) {
      await act(async () => {
        root.render(ui);
      });
      // A second turn: the mount effect's fetch resolves on a microtask, and
      // its state lands in a further render.
      await act(async () => {
        await new Promise((resolve) => setTimeout(resolve, 0));
      });
    },
    async inFrame(ui, fn) {
      // Inside the frame we are deliberately OUTSIDE `act` — that is the whole
      // point — so silence act's environment warnings for its duration instead
      // of letting them drown out a genuine one.
      const prev = env.IS_REACT_ACT_ENVIRONMENT;
      env.IS_REACT_ACT_ENVIRONMENT = false;
      try {
        flushSync(() => {
          root.render(ui);
        });
        await fn();
      } finally {
        env.IS_REACT_ACT_ENVIRONMENT = prev;
      }
    },
    async unmount() {
      await act(async () => {
        root.unmount();
      });
      container.remove();
    },
  };
}

/** A plain bubbling click, unwrapped by `act`. */
export function rawClick(el: Element): void {
  el.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
}
