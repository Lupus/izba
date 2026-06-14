import { useEffect, useRef } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import { api, onShellOutput, onShellExit } from "../lib/ipc";

/** Interactive PTY into a guest, rendered with xterm.js. */
export function ShellView({ name }: { name: string }) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const term = new Terminal({ fontSize: 13, cursorBlink: true });
    const fit = new FitAddon();
    term.loadAddon(fit);
    if (ref.current) {
      term.open(ref.current);
      fit.fit();
    }

    let disposed = false;
    const unlisteners: Array<() => void> = [];
    const track = (p: Promise<() => void>) =>
      void p.then((un) => (disposed ? un() : unlisteners.push(un)));

    term.onData((d) => void api.shellWrite(name, d));

    const outSub = onShellOutput(name, (bytes) => term.write(bytes));
    const exitSub = onShellExit(name, () => {
      term.write("\r\n\x1b[2m[process exited]\x1b[0m\r\n");
      void api.shellClose(name);
    });
    track(outSub);
    track(exitSub);

    // Register the listeners BEFORE opening so no early PTY output is lost
    // (Tauri does not buffer events for listeners that attach later).
    void Promise.all([outSub, exitSub]).then(() => {
      if (disposed) return;
      api.shellOpen(name).then(
        () => {
          if (!disposed) void api.shellResize(name, term.cols, term.rows);
        },
        (e) => {
          if (!disposed) term.write(`\r\n\x1b[31m${e}\x1b[0m\r\n`);
        },
      );
    });

    const ro = new ResizeObserver(() => {
      fit.fit();
      void api.shellResize(name, term.cols, term.rows);
    });
    if (ref.current) ro.observe(ref.current);

    return () => {
      disposed = true;
      ro.disconnect();
      unlisteners.forEach((un) => un());
      void api.shellClose(name);
      term.dispose();
    };
  }, [name]);

  return <div ref={ref} className="h-full w-full" data-testid="shell-term" />;
}
