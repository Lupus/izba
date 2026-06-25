import { useState, type ReactNode } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

export function Section({ title, defaultOpen = true, children }: Readonly<{
  title: string; defaultOpen?: boolean; children: ReactNode;
}>) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <Card>
      <Button
        type="button"
        variant="ghost"
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm font-semibold justify-start"
      >
        <span className="text-muted-foreground-2">{open ? "▾" : "▸"}</span>
        {title}
      </Button>
      {open && <div className="border-t border-border p-3">{children}</div>}
    </Card>
  );
}
