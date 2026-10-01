/** Streamed daemon progress lines for a long-running dialog action. */
export function ProgressLog({ lines }: Readonly<{ lines: string[] }>) {
  if (lines.length === 0) return null;
  return (
    <div className="mt-3 max-h-24 overflow-auto rounded-lg bg-sidebar p-2 font-mono text-xs text-muted-foreground">
      {lines.map((m, i) => (
        <div key={i}>{m}</div>
      ))}
    </div>
  );
}
