import { useSyncExternalStore, useState, useEffect, useRef } from "react";
import { shellStore } from "../lib/shellStore";
import { api } from "../lib/ipc";

export function ShellPanel({ sandbox }: { sandbox: string }) {
  useSyncExternalStore(shellStore.subscribe, shellStore.snapshot);
  const all = shellStore.forSandbox(sandbox);
  // Restore the shell the user last had open (persisted across unmount), falling
  // back to the newest only if there is no valid remembered selection.
  const [activeId, setActiveIdState] = useState<string | null>(() => {
    const remembered = shellStore.getActive(sandbox);
    return remembered && all.some((s) => s.id === remembered) ? remembered : null;
  });
  const selectShell = (id: string) => {
    shellStore.setActive(sandbox, id);
    setActiveIdState(id);
  };

  // Auto-open exactly ONE shell per mount (a ref guards against StrictMode's
  // double-invoke AND the close-the-last-shell reopen loop). Once the user has
  // closed everything, we show an empty state instead of reopening.
  const autoOpened = useRef(false);
  useEffect(() => {
    if (all.length === 0 && !autoOpened.current) {
      autoOpened.current = true;
      void shellStore.open(sandbox);
      return;
    }
    if (all.length > 0 && (!activeId || !all.some((s) => s.id === activeId))) {
      const remembered = shellStore.getActive(sandbox);
      const restore =
        remembered && all.some((s) => s.id === remembered)
          ? remembered
          : all[all.length - 1].id;
      selectShell(restore);
    }
  }, [sandbox, all.length]); // eslint-disable-line react-hooks/exhaustive-deps

  const active = all.find((s) => s.id === activeId) ?? all[0] ?? null;

  return (
    <div className="flex h-full flex-col">
      <div role="tablist" className="flex items-center gap-1 border-b border-line pb-1">
        {all.map((s) => (
          <div
            key={s.id}
            className={
              "flex items-center gap-1 rounded-t px-2 py-1 text-xs " +
              (active && active.id === s.id ? "bg-hover font-semibold" : "text-ink-2")
            }
          >
            <button type="button" role="tab" onClick={() => selectShell(s.id)}>
              {s.label}
              {s.exited ? " (exited)" : ""}
            </button>
            <button
              type="button"
              aria-label={`Close ${s.label}`}
              onClick={() => void shellStore.close(s.id)}
              className="text-ink-3 hover:text-warn"
            >
              ×
            </button>
          </div>
        ))}
        <button
          type="button"
          aria-label="New shell"
          onClick={() => void shellStore.open(sandbox)}
          className="rounded px-2 py-1 text-xs text-ink-2 hover:bg-hover"
        >
          +
        </button>
      </div>
      <div className="min-h-0 flex-1">
        {active ? (
          <ShellViewer key={active.id} sandbox={sandbox} sessionKey={active.id} />
        ) : (
          <div className="flex h-full items-center justify-center text-sm text-ink-3">
            No shells. Click + to open one.
          </div>
        )}
      </div>
    </div>
  );
}

function ShellViewer({ sandbox, sessionKey }: { sandbox: string; sessionKey: string }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const s = shellStore.forSandbox(sandbox).find((x) => x.id === sessionKey);
    const host = ref.current;
    if (!s || !host) return;
    if (s.el.parentElement !== host) host.appendChild(s.el); // idempotent (StrictMode)
    if (!s.opened) {
      s.term.open(s.el);
      s.opened = true;
    }
    s.fit.fit();
    const ro = new ResizeObserver(() => {
      s.fit.fit();
      void api.shellResize(s.id, s.term.cols, s.term.rows);
    });
    ro.observe(host);
    void api.shellResize(s.id, s.term.cols, s.term.rows);
    return () => {
      ro.disconnect();
      if (s.el.parentElement === host) host.removeChild(s.el); // detach, do NOT dispose
    };
  }, [sandbox, sessionKey]);
  // overflow-hidden is load-bearing: xterm's own `.xterm-viewport` is the only
  // legitimate scroller (it owns the scrollback). On shrink, xterm leaves its
  // absolutely-positioned `.xterm-helper-textarea` parked at the old cursor's
  // pixel `top` (e.g. 780px from a former full-screen height); without clipping,
  // that stale element inflates scrollHeight up the whole flex chain into a
  // page-level scrollbar over empty space. Clipping here contains it.
  return <div ref={ref} data-testid="shell-host" className="h-full w-full overflow-hidden" />;
}
