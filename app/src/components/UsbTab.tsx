import { useEffect, useState } from "react";
import { api } from "../lib/ipc";
import type { UsbDevice, UsbStatus } from "../lib/types";
import { UsbConsentDialog } from "./UsbConsentDialog";
import { ConfirmDialog } from "./ConfirmDialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

/** What this tab actually KNOWS about the sandbox's USB grants.
 *
 *  "No devices granted." is an INVENTORY of a host-only consent record
 *  (`SandboxConfig.usb`), and this tab is where an operator answers "what
 *  physical hardware can this sandbox reach?". With the daemon unreachable, or
 *  `usb_status` refused because the sandbox is busy under `lock_sandbox`,
 *  `status` stays `null` and the tab used to answer "none" right beside its own
 *  error line. Nothing is written from that window — every write is per-row and
 *  there are no rows — but this project has already learned that a posture line
 *  gets read as an inventory. Not knowing is not the same as none. */
type LoadState = { kind: "loading" } | { kind: "ready" } | { kind: "error" };

interface Props {
  name: string;
  running: boolean;
  onChanged: () => void;
}

export function UsbTab({ name, running, onChanged }: Props) {
  // `null` = still loading; see UsbView for why that is worth distinguishing.
  const [configured, setConfigured] = useState<boolean | null>(null);
  const [status, setStatus] = useState<UsbStatus | null>(null);
  const [devices, setDevices] = useState<UsbDevice[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [granting, setGranting] = useState<UsbDevice | null>(null);
  const [revoking, setRevoking] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [loadState, setLoadState] = useState<LoadState>({ kind: "loading" });

  async function load() {
    try {
      const up = await api.usbUpstreamShow();
      setConfigured(up !== null);
      // The gate: with USB off, every other call refuses. Asking anyway would
      // turn "you have not set this up" into an error message.
      if (!up) return;
      const [s, devs] = await Promise.all([api.usbStatus(name), api.usbListDevices()]);
      setStatus(s);
      setDevices(devs);
      setError(null);
      setLoadState({ kind: "ready" });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      // A reload failing after a successful read leaves the inventory stale,
      // not unread — what is on screen is still something izba saw for THIS
      // sandbox (the effect below resets to `loading` when the sandbox
      // changes, so it can never be another sandbox's grants).
      setLoadState((prev) => (prev.kind === "ready" ? prev : { kind: "error" }));
    }
  }

  useEffect(() => {
    // A different sandbox is a different consent record: go back to "unknown"
    // rather than showing the previous sandbox's grants as this one's.
    setLoadState({ kind: "loading" });
    setStatus(null);
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [name, running]);

  async function act(fn: () => Promise<unknown>) {
    setBusy(true);
    setError(null);
    try {
      await fn();
      await load();
      onChanged();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  if (configured === false) {
    return (
      <div className="flex flex-col gap-2 text-sm">
        <div className="text-muted-foreground-2">USB passthrough is not configured.</div>
        <div className="text-muted-foreground">
          Set a usbip upstream in the Devices view to grant this sandbox a physical device.
        </div>
      </div>
    );
  }

  const granted = new Set((status?.grants ?? []).map((g) => g.device));
  // Only shared devices can be granted: an unshared one has nothing to import.
  const available = devices.filter((d) => !granted.has(d.device));
  const restartRequired = status?.restart_required ?? false;

  return (
    <div className="flex flex-col gap-4">
      {error && <div className="text-sm text-destructive">{error}</div>}

      {restartRequired && (
        <div className="flex flex-wrap items-center gap-3 rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          <span>
            This sandbox is running a kernel without USB support. The USB kernel is chosen at
            boot, so restart it to use the devices you granted.
          </span>
          <Button
            type="button"
            variant="secondary"
            size="sm"
            disabled={busy}
            onClick={() => void act(() => api.restart(name))}
          >
            Restart
          </Button>
        </div>
      )}

      <div>
        <div className="mb-1 text-xs font-medium text-muted-foreground">Granted devices</div>
        {loadState.kind !== "ready" ? (
          /* Deliberately distinct from a read-and-empty grant list. */
          <div className="text-sm text-muted-foreground-2">
            {loadState.kind === "loading"
              ? "izba has not read this sandbox's USB grants yet."
              : "izba could not read this sandbox's USB grants (see the error above) — not knowing which devices are granted is not the same as none being granted."}
          </div>
        ) : (status?.grants ?? []).length === 0 ? (
          <div className="text-sm text-muted-foreground-2">No devices granted.</div>
        ) : (
          <table className="w-full text-sm">
            <tbody>
              {(status?.grants ?? []).map((g) => (
                <tr key={g.device} className="border-t border-border">
                  <td className="py-2">
                    <span className="font-mono">{g.device}</span>
                    {g.description && (
                      <small className="block text-muted-foreground-2">{g.description}</small>
                    )}
                  </td>
                  <td className="py-2">
                    <div className="flex flex-wrap gap-1.5">
                      {g.busid_pin && <Badge variant="secondary">pinned {g.busid_pin}</Badge>}
                      {g.attached && <Badge variant="success">attached</Badge>}
                    </div>
                  </td>
                  <td className="py-2 text-right">
                    <div className="flex justify-end gap-1.5">
                      {g.attached ? (
                        <Button
                          type="button"
                          variant="secondary"
                          size="sm"
                          disabled={busy}
                          onClick={() => void act(() => api.usbDetach(name, g.device))}
                        >
                          Detach
                        </Button>
                      ) : (
                        // No Attach button on a stopped sandbox or one whose
                        // kernel cannot honour the grant: offering an action
                        // that cannot work is worse than not offering one.
                        running &&
                        !restartRequired && (
                          <Button
                            type="button"
                            variant="secondary"
                            size="sm"
                            disabled={busy}
                            onClick={() => void act(() => api.usbAttach(name, g.device))}
                          >
                            Attach
                          </Button>
                        )
                      )}
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        aria-label={`Revoke ${g.device}`}
                        disabled={busy}
                        onClick={() => setRevoking(g.device)}
                      >
                        Revoke
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div>
        <div className="mb-1 text-xs font-medium text-muted-foreground">Available devices</div>
        {loadState.kind !== "ready" ? (
          <div className="text-sm text-muted-foreground-2">
            The upstream&apos;s device list is unknown.
          </div>
        ) : available.length === 0 ? (
          <div className="text-sm text-muted-foreground-2">
            Nothing else on the upstream to grant.
          </div>
        ) : (
          <table className="w-full text-sm">
            <tbody>
              {available.map((d) => (
                <tr key={`${d.busid}:${d.device}`} className="border-t border-border align-top">
                  <td className="py-2">
                    <span className="font-mono">{d.device}</span>
                    <small className="block text-muted-foreground-2">{d.description}</small>
                    {d.bind_command && (
                      <div className="mt-1 text-xs text-muted-foreground-2">
                        Not shared yet — run{" "}
                        <code className="select-all font-mono">{d.bind_command}</code> elevated
                        on the USB host. izba never runs this for you.
                      </div>
                    )}
                  </td>
                  <td className="py-2">
                    {d.attached_to && d.attached_to !== name && (
                      <Badge variant="warning">attached to {d.attached_to}</Badge>
                    )}
                  </td>
                  <td className="py-2 text-right">
                    {d.shared && (
                      <Button
                        type="button"
                        variant="secondary"
                        size="sm"
                        aria-label={`Allow ${d.device}`}
                        disabled={busy}
                        onClick={() => setGranting(d)}
                      >
                        Allow…
                      </Button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {granting && (
        <UsbConsentDialog
          device={granting.device}
          description={granting.description}
          sandbox={name}
          onCancel={() => setGranting(null)}
          onConfirm={() => {
            const device = granting.device;
            setGranting(null);
            void act(() => api.usbAllow(name, device, null));
          }}
        />
      )}

      {revoking && (
        <ConfirmDialog
          title={`Revoke ${revoking} from ${name}?`}
          message="If the device is attached it is pulled out of the sandbox immediately — the guest sees an unplug."
          confirmLabel="Revoke"
          danger
          onCancel={() => setRevoking(null)}
          onConfirm={() => {
            const device = revoking;
            setRevoking(null);
            void act(() => api.usbRevoke(name, device));
          }}
        />
      )}
    </div>
  );
}
