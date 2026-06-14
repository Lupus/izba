import { useState } from "react";
import type { SandboxView } from "../lib/types";
import { StatusDot } from "./StatusDot";
import { ConfirmDialog } from "./ConfirmDialog";
import { api } from "../lib/ipc";

interface Props {
  sandbox: SandboxView | null;
  onChanged: () => void;
}

type Pending = { kind: "stop" | "remove"; name: string } | null;

export function Detail({ sandbox, onChanged }: Props) {
  const [busy, setBusy] = useState(false);
  const [pending, setPending] = useState<Pending>(null);
  const [error, setError] = useState<string | null>(null);

  if (!sandbox) {
    return <div className="flex-1 grid place-items-center text-ink-3">Select a sandbox</div>;
  }

  const running = sandbox.state.kind !== "stopped";
  const name = sandbox.name;

  async function act(fn: () => Promise<unknown>) {
    setBusy(true);
    setError(null);
    try {
      await fn();
      onChanged();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="flex-1 p-5">
      <div className="flex items-center gap-3 text-lg font-semibold">
        <StatusDot state={sandbox.state} /> {name}
      </div>
      <div className="mt-1 text-ink-2">{sandbox.image}</div>
      {sandbox.state.kind === "degraded" && (
        <div className="mt-3 rounded-lg border border-warn/30 bg-warn/5 px-3 py-2 text-warn text-sm">
          {sandbox.state.reason}
        </div>
      )}

      <div className="mt-4 flex flex-wrap gap-2">
        {running ? (
          <button
            type="button"
            disabled={busy}
            onClick={() => setPending({ kind: "stop", name })}
            className="rounded-lg border border-line px-3 py-1.5 hover:bg-hover disabled:opacity-50"
          >
            Stop
          </button>
        ) : (
          <button
            type="button"
            disabled={busy}
            onClick={() => void act(() => api.start(name))}
            className="rounded-lg bg-accent px-3 py-1.5 font-semibold text-white shadow-sm disabled:opacity-50"
          >
            Start
          </button>
        )}
        <button
          type="button"
          disabled={busy}
          onClick={() => void act(() => api.restart(name))}
          className="rounded-lg border border-line px-3 py-1.5 hover:bg-hover disabled:opacity-50"
        >
          Restart
        </button>
        <button
          type="button"
          disabled={busy}
          onClick={() => setPending({ kind: "remove", name })}
          className="rounded-lg border border-warn/40 px-3 py-1.5 text-warn hover:bg-warn/5 disabled:opacity-50"
        >
          Remove
        </button>
      </div>

      {error && <div className="mt-3 text-warn text-sm">{error}</div>}

      {pending?.kind === "stop" && (
        <ConfirmDialog
          title={`Stop ${pending.name}?`}
          message="The VM is shut down; the sandbox keeps its disk and can be started again."
          confirmLabel="Stop"
          onCancel={() => setPending(null)}
          onConfirm={() => {
            setPending(null);
            void act(() => api.stop(pending.name));
          }}
        />
      )}
      {pending?.kind === "remove" && (
        <ConfirmDialog
          title={`Remove ${pending.name}?`}
          message="This permanently deletes the sandbox and its writable disk."
          confirmLabel="Remove"
          danger
          onCancel={() => setPending(null)}
          onConfirm={() => {
            setPending(null);
            void act(() => api.remove(pending.name, false));
          }}
        />
      )}
    </section>
  );
}
