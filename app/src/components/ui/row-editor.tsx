import * as React from "react";
import { Plus, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export function RowList({ children, className }: { children: React.ReactNode; className?: string }) {
  return <div className={cn("flex flex-col gap-2", className)}>{children}</div>;
}

export function RowCard({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={cn("flex items-center gap-2 rounded-lg border border-border p-2", className)}>
      {children}
    </div>
  );
}

export function AddRowButton({
  onClick,
  children,
  disabled,
}: {
  onClick: () => void;
  children: React.ReactNode;
  disabled?: boolean;
}) {
  return (
    <Button
      type="button"
      variant="outline"
      onClick={onClick}
      disabled={disabled}
      // Solid, surface-independent background so it looks identical over a
      // card (white) or a plain section (gray) — fixes the transparent-secondary
      // white-vs-gray drift. Default size = Input height (py-1.5).
      // self-start shrinks to content in a flex parent; justify-self-start does
      // the same in a grid parent (e.g. PortsTab's create-form) — keep both so
      // the button never stretches full-width regardless of container.
      className="self-start justify-self-start gap-1.5 bg-card hover:bg-muted"
    >
      <Plus className="h-4 w-4" />
      {children}
    </Button>
  );
}

export function RemoveRowButton({
  onClick,
  disabled,
  ...aria
}: {
  onClick: () => void;
  disabled?: boolean;
  "aria-label": string;
}) {
  return (
    <Button type="button" variant="destructive" size="sm" onClick={onClick} disabled={disabled} aria-label={aria["aria-label"]}>
      <X className="h-3.5 w-3.5" />
    </Button>
  );
}
