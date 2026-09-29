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
}: Readonly<{ name: string; lockdown: LockdownView; onChanged: () => void }>) {
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
  const summary = lockdown.locked
    ? `locked · ${lockdown.account} · ${lockdown.net_blocked ? "network blocked" : "network open"}`
    : "unlocked";
  const badge = lockdown.restart_required
    ? lockdown.locked
      ? "restart to apply"
      : "still running as account — restart to apply"
    : null;

  return (
    <>
      <Row label="lock-down">
        <span className="inline-flex flex-wrap items-center gap-2">
          <span>{summary}</span>
          {badge && <span className="text-xs text-warning">{badge}</span>}
          {lockdown.locked ? (
            <Button variant="ghost" size="sm" disabled={pending} onClick={() => setConfirming(true)}>
              {pending ? (
                <>
                  <Spinner /> Waiting for approval…
                </>
              ) : (
                "Unlock"
              )}
            </Button>
          ) : (
            <Button
              variant="secondary"
              size="sm"
              disabled={pending}
              title="Requires administrator approval (UAC)"
              onClick={() => void run(() => api.lockdown(name))}
            >
              {pending ? (
                <>
                  <Spinner /> Waiting for approval…
                </>
              ) : (
                <>
                  <ShieldCheck /> Lock down
                </>
              )}
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
          message="After the next restart the sandbox's VMM will run as your own user, with network access, instead of the locked-down account. Requires administrator approval (UAC)."
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
