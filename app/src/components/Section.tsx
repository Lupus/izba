import { useState, type ReactNode } from "react";

export function Section({ title, defaultOpen = true, children }: Readonly<{
  title: string; defaultOpen?: boolean; children: ReactNode;
}>) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <section className="rounded-lg border border-line">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm font-semibold"
      >
        <span className="text-ink-3">{open ? "▾" : "▸"}</span>
        {title}
      </button>
      {open && <div className="border-t border-line p-3">{children}</div>}
    </section>
  );
}
