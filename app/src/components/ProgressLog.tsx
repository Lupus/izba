/** Streamed daemon progress lines for a long-running dialog action. */
export function ProgressLog({ lines }: Readonly<{ lines: string[] }>) {
  if (lines.length === 0) return null;
  // The same message can arrive twice; key each line by its text plus how
  // many times that text has been seen, which is stable as lines append.
  const seen = new Map<string, number>();
  const rows = lines.map((text) => {
    const n = (seen.get(text) ?? 0) + 1;
    seen.set(text, n);
    return { key: `${text}#${n}`, text };
  });
  return (
    <div className="mt-3 max-h-24 overflow-auto rounded-lg bg-sidebar p-2 font-mono text-xs text-muted-foreground">
      {rows.map((r) => (
        <div key={r.key}>{r.text}</div>
      ))}
    </div>
  );
}
