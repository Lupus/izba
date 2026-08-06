import { useEffect, useState } from "react";
import { api } from "../lib/ipc";
import type { UsbDevice, UsbUpstream } from "../lib/types";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Card, CardContent } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";

/** Trust classes that deserve a red box rather than a note. */
const LOUD_TRUST = new Set(["private-lan", "public"]);

const DEFAULT_PORT = 3240;

export function UsbView() {
  // `null` = still loading. Distinguishing that from "off" matters: rendering
  // the setup panel for a split second on every open reads as a broken feature.
  const [configured, setConfigured] = useState<boolean | null>(null);
  const [upstream, setUpstream] = useState<UsbUpstream | null>(null);
  const [devices, setDevices] = useState<UsbDevice[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);
  const [host, setHost] = useState("");
  const [port, setPort] = useState(String(DEFAULT_PORT));
  const [allowRemote, setAllowRemote] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function load() {
    try {
      const up = await api.usbUpstreamShow();
      setUpstream(up);
      setConfigured(up !== null);
      // The gate: every other USB call refuses while the feature is off, so
      // asking one of them to find that out would render a scary error for an
      // entirely ordinary state.
      if (!up) {
        setDevices([]);
        setError(null);
        return;
      }
      setDevices(await api.usbListDevices());
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function saveUpstream() {
    const p = Number(port);
    if (!host.trim() || !Number.isInteger(p) || p < 1 || p > 65535) {
      setError("Enter a host and a port between 1 and 65535.");
      return;
    }
    setBusy(true);
    try {
      await api.usbUpstreamSet(host.trim(), p, allowRemote);
      setEditing(false);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function copy(cmd: string) {
    try {
      await navigator.clipboard.writeText(cmd);
      setCopied(cmd);
    } catch {
      // Clipboard access can be refused. The command is on screen and
      // selectable, so say that rather than failing silently.
      setError("Could not copy — select the command above and copy it manually.");
    }
  }

  function startEditing() {
    setHost(upstream?.host ?? "");
    setPort(String(upstream?.port ?? DEFAULT_PORT));
    setAllowRemote(false);
    setEditing(true);
  }

  return (
    <section className="flex flex-1 flex-col gap-4 overflow-y-auto p-5">
      <div className="text-lg font-semibold">USB devices</div>

      {error && <div className="text-sm text-destructive">{error}</div>}

      {configured === false && !editing && (
        <Card>
          <CardContent className="flex flex-col items-start gap-2 pt-5 text-sm">
            <div className="font-medium">USB passthrough is not configured.</div>
            <p className="text-muted-foreground">
              izba reaches physical devices through a usbip server on the machine they are
              plugged into — on Windows that is usbipd-win. Point izba at it to begin.
            </p>
            <Button type="button" onClick={startEditing}>
              Configure upstream
            </Button>
          </CardContent>
        </Card>
      )}

      {configured && upstream && !editing && (
        <Card>
          <CardContent className="flex flex-col gap-2 pt-5 text-sm">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono">
                {upstream.host}:{upstream.port}
              </span>
              {upstream.resolved && upstream.resolved !== upstream.host && (
                <span className="text-muted-foreground-2">→ {upstream.resolved}</span>
              )}
              <Badge variant={LOUD_TRUST.has(upstream.trust) ? "warning" : "secondary"}>
                {upstream.trust}
              </Badge>
              <Button type="button" variant="secondary" size="sm" onClick={startEditing}>
                Change
              </Button>
              <Button type="button" variant="secondary" size="sm" onClick={() => void load()}>
                Refresh
              </Button>
            </div>
            {upstream.warning && (
              <div
                className={
                  LOUD_TRUST.has(upstream.trust)
                    ? "rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-destructive"
                    : "text-muted-foreground"
                }
              >
                {upstream.warning}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {editing && (
        <Card>
          <CardContent className="flex flex-col gap-3 pt-5 text-sm">
            <div className="flex flex-wrap items-end gap-2">
              <div className="grid gap-1">
                <label htmlFor="usb-host" className="text-xs font-medium">
                  Host
                </label>
                <Input
                  id="usb-host"
                  aria-label="Host"
                  placeholder="127.0.0.1"
                  value={host}
                  onChange={(e) => setHost(e.target.value)}
                  className="w-56"
                />
              </div>
              <div className="grid gap-1">
                <label htmlFor="usb-port" className="text-xs font-medium">
                  Port
                </label>
                <Input
                  id="usb-port"
                  aria-label="Port"
                  inputMode="numeric"
                  value={port}
                  onChange={(e) => setPort(e.target.value)}
                  className="w-24"
                />
              </div>
            </div>
            <label className="flex items-center gap-2 text-sm">
              <Checkbox
                aria-label="Allow a globally routable upstream"
                checked={allowRemote}
                onCheckedChange={(v) => setAllowRemote(v === true)}
              />
              Allow a globally routable upstream (not recommended — usbip has no
              authentication and no encryption)
            </label>
            <div className="flex gap-2">
              <Button type="button" disabled={busy} onClick={() => void saveUpstream()}>
                Save
              </Button>
              <Button type="button" variant="ghost" onClick={() => setEditing(false)}>
                Cancel
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {configured && devices.length === 0 && !error && (
        <div className="text-sm text-muted-foreground-2">
          The upstream shares no devices. Plug one in and share it on the USB host, then
          Refresh.
        </div>
      )}

      {configured && devices.length > 0 && (
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-xs text-muted-foreground-2">
              <th className="pb-1 font-normal">Device</th>
              <th className="pb-1 font-normal">Bus id</th>
              <th className="pb-1 font-normal">State</th>
            </tr>
          </thead>
          <tbody>
            {devices.map((d) => (
              <tr key={`${d.busid}:${d.device}`} className="border-t border-border align-top">
                <td className="py-2">
                  <span className="font-mono">{d.device}</span>
                  <small className="block text-muted-foreground-2">{d.description}</small>
                  {d.bind_command && (
                    <div className="mt-1 flex flex-wrap items-center gap-2">
                      <code className="select-all rounded bg-muted px-1.5 py-0.5 font-mono text-xs">
                        {d.bind_command}
                      </code>
                      <Button
                        type="button"
                        variant="secondary"
                        size="sm"
                        aria-label={`Copy the share command for ${d.device}`}
                        onClick={() => void copy(d.bind_command as string)}
                      >
                        {copied === d.bind_command ? "Copied" : "Copy"}
                      </Button>
                      <span className="text-xs text-muted-foreground-2">
                        izba never runs this for you — it needs Administrator on the USB host.
                      </span>
                    </div>
                  )}
                </td>
                <td className="py-2 font-mono">{d.busid}</td>
                <td className="py-2">
                  <div className="flex flex-wrap gap-1.5">
                    <Badge variant={d.shared ? "secondary" : "warning"}>
                      {d.shared ? "shared" : "not shared"}
                    </Badge>
                    {d.attached_to && (
                      <Badge variant="success">attached to {d.attached_to}</Badge>
                    )}
                    {d.granted_to.map((s) => (
                      <Badge key={s}>granted to {s}</Badge>
                    ))}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {configured && (
        <p className="text-xs text-muted-foreground-2">
          Grant a device to a sandbox from its USB tab.
        </p>
      )}
    </section>
  );
}
