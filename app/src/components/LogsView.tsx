import { useEffect, useRef, useState } from "react";
import { api } from "../lib/ipc";

/** Live-tailing view of a sandbox's captured console output. */
export function LogsView({ name }: { name: string }) {
  const [text, setText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const preRef = useRef<HTMLPreElement>(null);

  useEffect(() => {
    let alive = true;
    async function tick() {
      try {
        const t = await api.readLogs(name);
        if (!alive) return;
        setText(t);
        setError(null);
      } catch (e) {
        if (!alive) return;
        setError(e instanceof Error ? e.message : String(e));
      }
    }
    void tick();
    const id = setInterval(() => void tick(), 1500);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [name]);

  // Keep the view pinned to the newest output.
  useEffect(() => {
    const el = preRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [text]);

  return (
    <div className="flex h-full flex-col">
      {error && <div className="mb-2 text-sm text-destructive">{error}</div>}
      <pre
        ref={preRef}
        data-testid="log-output"
        className="flex-1 overflow-auto whitespace-pre-wrap rounded-lg bg-muted p-3 font-mono text-xs text-foreground"
      >
        {text || "No console output yet."}
      </pre>
    </div>
  );
}
