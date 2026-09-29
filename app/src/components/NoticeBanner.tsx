import { Button } from "@/components/ui/button";

/** App-level, dismissible notice. Lives above the Detail pane so guidance about
 *  a sandbox that no longer exists (e.g. an orphaned lock-down account after
 *  remove) outlives the Detail that raised it. */
export function NoticeBanner({ notice, onDismiss }: Readonly<{ notice: string | null; onDismiss: () => void }>) {
  if (notice === null) return null;
  return (
    <div
      role="alert"
      className="flex items-start justify-between gap-3 border-b border-destructive/30 bg-destructive/10 px-4 py-2 text-sm text-destructive"
    >
      <span>{notice}</span>
      <Button variant="ghost" size="sm" onClick={onDismiss}>
        Dismiss
      </Button>
    </div>
  );
}
