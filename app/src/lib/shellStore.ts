import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import { api, onShellOutput, onShellExit } from "./ipc";

export interface ShellSession {
  id: string;
  sandbox: string;
  label: string;
  term: Terminal;
  fit: FitAddon;
  el: HTMLDivElement; // kept alive; portaled into the active viewer
  opened: boolean; // term.open(el) called once
  exited: boolean;
  unlisten: Array<() => void>;
}

const sessions: ShellSession[] = [];
// The shell tab the user last had open, per sandbox. Survives the panel
// unmounting (e.g. switching to Netlog and back) so we reopen what they left on
// instead of jumping to the newest shell.
const activeBySandbox: Record<string, string> = {};
const listeners = new Set<() => void>();
// Client-minted session ids (a plain counter, NOT crypto, for test determinism).
let seq = 0;
// useSyncExternalStore requires a STABLE snapshot reference between renders, but a
// FRESH one on change (else it never re-renders). We cache a copy and rebuild it
// only inside emit() — so identity changes exactly when the session set changes.
let snap: readonly ShellSession[] = sessions.slice();
const emit = () => {
  snap = sessions.slice();
  listeners.forEach((l) => l());
};

export const shellStore = {
  subscribe(l: () => void) {
    listeners.add(l);
    return () => listeners.delete(l);
  },
  snapshot() {
    return snap;
  },
  forSandbox(sandbox: string) {
    return sessions.filter((s) => s.sandbox === sandbox);
  },

  /** The remembered active shell id for a sandbox, or undefined if none. */
  getActive(sandbox: string): string | undefined {
    return activeBySandbox[sandbox];
  },
  /** Remember `id` as the active shell for `sandbox`. */
  setActive(sandbox: string, id: string) {
    activeBySandbox[sandbox] = id;
  },

  async open(sandbox: string): Promise<string> {
    const id = `sh-${seq++}`;
    const el = document.createElement("div");
    el.style.width = "100%";
    el.style.height = "100%";
    const term = new Terminal({ fontSize: 13, cursorBlink: true });
    const fit = new FitAddon();
    term.loadAddon(fit);
    const session: ShellSession = {
      id,
      sandbox,
      label: "",
      term,
      fit,
      el,
      opened: false,
      exited: false,
      unlisten: [],
    };
    sessions.push(session);
    session.label = `Shell ${sessions.filter((s) => s.sandbox === sandbox).length}`;
    emit();
    // Subscribe BEFORE opening the backend shell so no early output is lost.
    const outUn = await onShellOutput(id, (bytes) => term.write(bytes));
    const exitUn = await onShellExit(id, () => {
      session.exited = true;
      term.write("\r\n\x1b[2m[process exited]\x1b[0m\r\n");
      emit();
    });
    session.unlisten.push(outUn, exitUn);
    term.onData((d) => void api.shellWrite(id, d));
    try {
      await api.shellOpen(sandbox, id);
    } catch (e) {
      // Clean up the failed session rather than leaving a zombie tab.
      outUn();
      exitUn();
      term.dispose();
      el.remove();
      const i = sessions.findIndex((s) => s.id === id);
      if (i >= 0) sessions.splice(i, 1);
      emit();
      throw e;
    }
    emit();
    return id;
  },

  async close(id: string) {
    const i = sessions.findIndex((s) => s.id === id);
    if (i < 0) return;
    const s = sessions[i];
    sessions.splice(i, 1);
    // Drop the remembered-active pointer if it referenced the closed shell, so a
    // stale id never sticks; the panel then falls back to the newest shell.
    if (activeBySandbox[s.sandbox] === id) delete activeBySandbox[s.sandbox];
    emit();
    s.unlisten.forEach((u) => u());
    if (s.id) await api.shellClose(s.id).catch(() => {});
    s.term.dispose();
    s.el.remove();
  },
};
