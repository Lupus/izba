import * as React from "react";
import { X } from "lucide-react";
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
    <Button type="button" variant="secondary" size="sm" onClick={onClick} disabled={disabled} className="justify-self-start self-start">
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
