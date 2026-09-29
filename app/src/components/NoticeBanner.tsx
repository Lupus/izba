import { Button } from "@/components/ui/button";

/** Append `msg` unless an identical notice is already listed (same list back). */
export function appendNotice(list: string[], msg: string): string[] {
  return list.includes(msg) ? list : [...list, msg];
}

/** App-level, dismissible notices. Live above the Detail pane so guidance about
 *  a sandbox that no longer exists (e.g. an orphaned lock-down account after
 *  remove) outlives the Detail that raised it; each notice is kept until the
 *  user dismisses it, so a later one never replaces an earlier instruction. */
export function NoticeBanner({
  notices,
  onDismiss,
}: Readonly<{ notices: string[]; onDismiss: (index: number) => void }>) {
  return (
    <>
      {notices.map((notice, i) => (
        <div
          key={notice}
          role="alert"
          className="flex items-start justify-between gap-3 border-b border-destructive/30 bg-destructive/10 px-4 py-2 text-sm text-destructive"
        >
          <span>{notice}</span>
          <Button variant="ghost" size="sm" aria-label={`Dismiss notice ${i + 1}`} onClick={() => onDismiss(i)}>
            Dismiss
          </Button>
        </div>
      ))}
    </>
  );
}
