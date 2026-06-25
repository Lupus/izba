import { useSyncExternalStore, useState, useEffect, useRef } from "react";
import { shellStore } from "../lib/shellStore";
import { api } from "../lib/ipc";
import { Button } from "@/components/ui/button";

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
  // Opening a shell makes it the active tab — that's what the user expects when
  // clicking "＋" or first entering the panel.
  const openShell = async () => {
    const id = await shellStore.open(sandbox);
    selectShell(id);
  };

  // Auto-open exactly ONE shell per mount (a ref guards against StrictMode's
  // double-invoke AND the close-the-last-shell reopen loop). Once the user has
  // closed everything, we show an empty state instead of reopening.
  const autoOpened = useRef(false);
  useEffect(() => {
    if (all.length === 0 && !autoOpened.current) {
      autoOpened.current = true;
      void openShell();
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
      <div role="tablist" className="flex items-center gap-1 border-b border-border pb-1">
        {all.map((s) => (
          <div
            key={s.id}
            className={
              "flex items-center gap-1 rounded-t px-2 py-1 text-xs " +
              (active && active.id === s.id ? "bg-muted font-semibold" : "text-muted-foreground")
            }
          >
            <Button
              variant="ghost"
              size="sm"
              role="tab"
              className="h-auto p-0 text-xs font-normal hover:bg-transparent"
              onClick={() => selectShell(s.id)}
            >
              {s.label}
              {s.exited ? " (exited)" : ""}
            </Button>
            <Button
              variant="ghost"
              size="icon"
              aria-label={`Close ${s.label}`}
              className="h-4 w-4 text-muted-foreground-2 hover:bg-transparent hover:text-destructive"
              onClick={() => void shellStore.close(s.id)}
            >
              ×
            </Button>
          </div>
        ))}
        <Button
          variant="ghost"
          size="sm"
          aria-label="New shell"
          className="text-muted-foreground hover:bg-muted"
          onClick={() => void openShell()}
        >
          +
        </Button>
      </div>
      <div className="min-h-0 flex-1">
        {active ? (
          <ShellViewer key={active.id} sandbox={sandbox} sessionKey={active.id} />
        ) : (
          <div className="flex h-full items-center justify-center text-sm text-muted-foreground-2">
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
