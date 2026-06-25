import { useEffect, useState } from "react";
import { openUrl } from "@tauri-apps/plugin-opener";
import { api } from "../lib/ipc";
import type { SandboxView, PortRule } from "../lib/types";
import { isValidPort, isValidBind } from "../lib/portvalidate";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { AddRowButton, RemoveRowButton } from "@/components/ui/row-editor";

interface Props {
  sandbox: SandboxView;
}

const persistedKey = (r: PortRule) => `${r.bind}:${r.host_port}:${r.guest_port}`;

export function PortsTab({ sandbox }: Props) {
  const [live, setLive] = useState<PortRule[]>([]);
  const [persisted, setPersisted] = useState<PortRule[]>([]);
  const [error, setError] = useState<string | null>(null);

  // add-forward form state
  const [newBind, setNewBind] = useState("");
  const [newHost, setNewHost] = useState("");
  const [newGuest, setNewGuest] = useState("");
  const [formError, setFormError] = useState<string | null>(null);

  const running = sandbox.state.kind !== "stopped";

  async function reload() {
    try {
      const [liveRules, detail] = await Promise.all([
        api.portList(sandbox.name),
        api.inspect(sandbox.name),
      ]);
      setLive(liveRules);
      setPersisted(detail.ports);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  useEffect(() => {
    void reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sandbox.name, sandbox.state.kind]);

  async function makePersistent(rule: PortRule) {
    try {
      await api.portPublish(sandbox.name, persistedKey(rule), true);
      await reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  async function remove(rule: PortRule) {
    try {
      await api.portUnpublish(sandbox.name, rule.bind, rule.host_port);
      await reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  async function addForward() {
    if (!isValidPort(newHost) || !isValidPort(newGuest) || !isValidBind(newBind)) {
      setFormError(
        "Host and guest ports must be 1–65535; bind must be a valid IPv4 or empty.",
      );
      return;
    }
    setFormError(null);
    const ruleStr = newBind.trim()
      ? `${newBind.trim()}:${newHost.trim()}:${newGuest.trim()}`
      : `${newHost.trim()}:${newGuest.trim()}`;
    try {
      await api.portPublish(sandbox.name, ruleStr, false);
      setNewBind("");
      setNewHost("");
      setNewGuest("");
      await reload();
    } catch (e) {
      setFormError(e instanceof Error ? e.message : String(e));
    }
  }

  // Build display rows: union of live + persisted-only (persisted but no live relay)
  const persistedKeys = new Set(persisted.map(persistedKey));
  const liveKeys = new Set(live.map(persistedKey));
  const persistedOnly = persisted.filter((r) => !liveKeys.has(persistedKey(r)));
  const rows: Array<{ rule: PortRule; isPersisted: boolean; isLive: boolean }> = [
    ...live.map((r) => ({ rule: r, isPersisted: persistedKeys.has(persistedKey(r)), isLive: true })),
    ...persistedOnly.map((r) => ({ rule: r, isPersisted: true, isLive: false })),
  ];

  return (
    <div className="flex flex-col gap-4">
      {error && <div className="text-sm text-destructive">{error}</div>}

      {rows.length === 0 && !error && (
        <div className="text-sm text-muted-foreground-2">No port forwards active.</div>
      )}

      {rows.length > 0 && (
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-xs text-muted-foreground-2">
              <th className="pb-1 font-normal">Forward</th>
              <th className="pb-1 font-normal" />
              <th className="pb-1 font-normal" />
            </tr>
          </thead>
          <tbody>
            {rows.map(({ rule: r, isPersisted, isLive }) => (
              <tr key={persistedKey(r)} className="border-t border-border">
                <td className="py-2 font-mono">
                  {r.bind}:{r.host_port} → {r.guest_port}
                  {!isPersisted && (
                    <Badge variant="warning" className="ml-2">
                      active until restart
                    </Badge>
                  )}
                </td>
                <td className="py-2 pl-2">
                  <div className="flex gap-1.5">
                    {isLive && (
                      <Button
                        type="button"
                        variant="secondary"
                        size="sm"
                        aria-label={`Open port ${r.host_port} in browser`}
                        onClick={() => void openUrl(`http://127.0.0.1:${r.host_port}`)}
                      >
                        Open in browser
                      </Button>
                    )}
                    {!isPersisted && (
                      <Button
                        type="button"
                        variant="secondary"
                        size="sm"
                        onClick={() => void makePersistent(r)}
                      >
                        Make persistent
                      </Button>
                    )}
                  </div>
                </td>
                <td className="py-2 pl-2 text-right">
                  <RemoveRowButton
                    aria-label={`Remove port ${r.host_port}`}
                    onClick={() => void remove(r)}
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <div className="mt-2 grid gap-2">
        <span className="text-xs font-medium text-muted-foreground">Add forward</span>
        <div className="flex flex-wrap items-center gap-2">
          <Input
            aria-label="Bind address"
            placeholder="127.0.0.1"
            value={newBind}
            disabled={!running}
            onChange={(e) => setNewBind(e.target.value)}
            className="w-32"
          />
          <Input
            aria-label="Host port"
            placeholder="host"
            inputMode="numeric"
            value={newHost}
            disabled={!running}
            onChange={(e) => setNewHost(e.target.value)}
            className="w-20"
          />
          <span className="text-muted-foreground-2">:</span>
          <Input
            aria-label="Guest port"
            placeholder="guest"
            inputMode="numeric"
            value={newGuest}
            disabled={!running}
            onChange={(e) => setNewGuest(e.target.value)}
            className="w-20"
          />
          <AddRowButton disabled={!running} onClick={() => void addForward()}>
            Add forward
          </AddRowButton>
        </div>
        {formError && <span className="text-xs text-destructive">{formError}</span>}
      </div>
    </div>
  );
}
