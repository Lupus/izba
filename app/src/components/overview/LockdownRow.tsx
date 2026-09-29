import { useEffect, useRef, useState } from "react";
import { ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Spinner } from "../Spinner";
import { ConfirmDialog } from "../ConfirmDialog";
import { Row } from "./CardShell";
import { api } from "../../lib/ipc";
import type { LockdownView } from "../../lib/types";

type Phase = { kind: "idle" } | { kind: "pending" } | { kind: "cancelled" } | { kind: "error"; message: string };

/** Per-sandbox Windows lock-down (MVP-D). Each action pops a UAC prompt; a
 *  declined prompt is the user's choice, not a failure. Takes effect at the
 *  next start — the badge is the daemon's recorded fact, never guessed here. */
export function LockdownRow({
  name,
  lockdown,
  onChanged,
  unknown = false,
}: Readonly<{
  name: string;
  lockdown: LockdownView;
  onChanged: () => void;
  /** The last posture refresh failed: the held `lockdown` may be out of date
   *  (e.g. the CLI changed it), so withhold the POSTURE and any control that
   *  STARTS an action. In-flight feedback (pending, error, cancelled, an open
   *  confirmation) still renders. */
  unknown?: boolean;
}>) {
  const [phase, setPhase] = useState<Phase>({ kind: "idle" });
  const [confirming, setConfirming] = useState(false);
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);

  const run = async (action: () => Promise<"locked" | "cancelled" | void>) => {
    setPhase({ kind: "pending" });
    try {
      const outcome = await action();
      if (!alive.current) return;
      setPhase(outcome === "cancelled" ? { kind: "cancelled" } : { kind: "idle" });
      if (outcome !== "cancelled") onChanged();
    } catch (e) {
      if (!alive.current) return;
      setPhase({ kind: "error", message: String(e) });
    }
  };

  const pending = phase.kind === "pending";
  const summary = unknown
    ? "unknown — refresh failed"
    : lockdown.locked
    ? `locked · ${lockdown.account} · ${lockdown.net_blocked ? "network blocked" : "network open"}`
    : "unlocked";
  const badge = !unknown && lockdown.restart_required
    ? lockdown.locked
      ? "restart to apply"
      : "still running as account — restart to apply"
    : null;

  return (
    <>
      <Row label="lock-down">
        <span className="inline-flex flex-wrap items-center gap-2">
          <span className={unknown ? "text-warning" : undefined}>{summary}</span>
          {badge && <span className="text-xs text-warning">{badge}</span>}
          {pending ? (
            <Button variant="ghost" size="sm" disabled>
              <Spinner /> Waiting for approval…
            </Button>
          ) : unknown ? null : lockdown.locked ? (
            <Button variant="ghost" size="sm" onClick={() => setConfirming(true)}>
              Unlock
            </Button>
          ) : (
            <Button
              variant="secondary"
              size="sm"
              title="Requires administrator approval (UAC)"
              onClick={() => void run(() => api.lockdown(name))}
            >
              <ShieldCheck /> Lock down
            </Button>
          )}
        </span>
      </Row>
      {phase.kind === "cancelled" && (
        <div className="pl-24 text-xs text-muted-foreground-2">cancelled — nothing changed</div>
      )}
      {phase.kind === "error" && (
        <div role="alert" className="pl-24 text-xs text-destructive">
          {phase.message}
        </div>
      )}
      {confirming && (
        <ConfirmDialog
          title="Unlock sandbox?"
          message={`The network block and the locked-down account are removed immediately. A running sandbox's VMM keeps running as the old account until its next restart, then runs as your own user with network access. Requires administrator approval (UAC).${
            unknown ? " The lock-down state is unknown right now — wait for it to refresh before unlocking." : ""
          }`}
          confirmDisabled={unknown}
          confirmLabel="Unlock sandbox"
          danger
          onCancel={() => setConfirming(false)}
          onConfirm={() => {
            setConfirming(false);
            void run(() => api.unlock(name));
          }}
        />
      )}
    </>
  );
}
