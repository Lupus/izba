import { useSyncExternalStore, useState, useEffect, useRef } from "react";
import { shellStore } from "../lib/shellStore";
import { api } from "../lib/ipc";

export function ShellPanel({ sandbox }: { sandbox: string }) {
  useSyncExternalStore(shellStore.subscribe, shellStore.snapshot);
  const all = shellStore.forSandbox(sandbox);
  const [activeId, setActiveId] = useState<string | null>(null);

  // Default the active tab to the first session; auto-open one if none exist.
  useEffect(() => {
    if (all.length === 0) {
      void shellStore.open(sandbox);
      return;
    }
    if (!activeId || !all.some((s) => s.id === activeId)) {
      setActiveId(all[all.length - 1].id || all[all.length - 1].label);
    }
  }, [sandbox, all.length]); // eslint-disable-line react-hooks/exhaustive-deps

  const active = all.find((s) => (s.id || s.label) === activeId) ?? all[0] ?? null;

  return (
    <div className="flex h-full flex-col">
      <div role="tablist" className="flex items-center gap-1 border-b border-line pb-1">
        {all.map((s) => {
          const key = s.id || s.label;
          return (
            <div
              key={key}
              className={
                "flex items-center gap-1 rounded-t px-2 py-1 text-xs " +
                (active && (active.id || active.label) === key
                  ? "bg-hover font-semibold"
                  : "text-ink-2")
              }
            >
              <button type="button" role="tab" onClick={() => setActiveId(key)}>
                {s.label}
                {s.exited ? " (exited)" : ""}
              </button>
              <button
                type="button"
                aria-label={`Close ${s.label}`}
                onClick={() => {
                  if (s.id) void shellStore.close(s.id);
                }}
                className="text-ink-3 hover:text-warn"
              >
                ×
              </button>
            </div>
          );
        })}
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
        {active && (
          <ShellViewer
            key={active.id || active.label}
            sandbox={sandbox}
            sessionKey={active.id || active.label}
          />
        )}
      </div>
    </div>
  );
}

function ShellViewer({ sandbox, sessionKey }: { sandbox: string; sessionKey: string }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const s = shellStore.forSandbox(sandbox).find((x) => (x.id || x.label) === sessionKey);
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
      if (s.id) void api.shellResize(s.id, s.term.cols, s.term.rows);
    });
    ro.observe(host);
    if (s.id) void api.shellResize(s.id, s.term.cols, s.term.rows);
    return () => {
      ro.disconnect();
      if (s.el.parentElement === host) host.removeChild(s.el); // detach, do NOT dispose
    };
  }, [sandbox, sessionKey]);
  return <div ref={ref} data-testid="shell-host" className="h-full w-full" />;
}
