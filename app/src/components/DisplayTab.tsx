import { useEffect, useRef, useState } from "react";
import { openUrl } from "@tauri-apps/plugin-opener";
import { api } from "../lib/ipc";
import type { SandboxDetail } from "../lib/types";
import { vncPresentation } from "../lib/vnc";
import { Button } from "@/components/ui/button";

interface Props {
  name: string;
  running: boolean;
  onChanged: () => void;
}

/** The destructive-tinted banner shared with `UsbTab` — same classes, so the
 *  two tabs' "something needs your attention" rows read identically. */
const BANNER =
  "flex flex-wrap items-center gap-3 rounded-lg border border-destructive/30 " +
  "bg-destructive/10 px-3 py-2 text-sm text-destructive";

/** A desktop takes seconds to come up (and can die) while the tab is open, so
 *  the tab re-inspects on a timer rather than only on mount — same cadence and
 *  in-flight-guard shape as `useStats`. Ticks stop with the effect. */
const POLL_MS = 3000;

/**
 * CREDENTIAL DISCIPLINE: `detail.vnc_url` carries the desktop's password in its
 * userinfo. It is only ever passed to `openUrl` or the clipboard — never
 * rendered, never logged, and never used as the iframe `src` (the iframe gets
 * the credential-less loopback proxy URL from `api.vncProxyStart`).
 */
export function DisplayTab({ name, running, onChanged }: Props) {
  const [detail, setDetail] = useState<SandboxDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [proxyUrl, setProxyUrl] = useState<string | null>(null);
  const [proxyError, setProxyError] = useState<string | null>(null);

  // Bumped whenever the tab moves to another sandbox (or unmounts). An answer
  // that started under an older generation describes a DIFFERENT sandbox and
  // must never paint: in this tab a wrong `detail` means the toolbar hands out
  // another sandbox's password-bearing URL.
  const generation = useRef(0);

  async function load(mine: number) {
    try {
      const d = await api.inspect(name);
      if (mine !== generation.current) return;
      setDetail(d);
      setError(null);
    } catch (e) {
      if (mine !== generation.current) return;
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  useEffect(() => {
    const mine = ++generation.current;
    // Overlap guard: a slow inspect must not stack ticks behind it.
    let inFlight = false;
    const tick = async () => {
      if (inFlight) return;
      inFlight = true;
      try {
        // `load` is generation-guarded, so a tick that lands after the tab
        // moved on (or unmounted) still cannot paint.
        await load(mine);
      } finally {
        inFlight = false;
      }
    };
    void tick();
    const timer = setInterval(() => void tick(), POLL_MS);
    return () => {
      clearInterval(timer);
      // Not a DOM ref: bumping the counter IS the cleanup, and reading its
      // latest value at teardown is exactly the intent the rule warns about.
      // eslint-disable-next-line react-hooks/exhaustive-deps
      generation.current++;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [name, running]);

  async function act(fn: () => Promise<unknown>) {
    // Captured before the call: a mutation for the sandbox we have since left
    // must not paint its result either — `load` here is this render's, bound
    // to this render's `name`.
    const mine = generation.current;
    setBusy(true);
    setError(null);
    try {
      await fn();
      await load(mine);
      if (mine === generation.current) onChanged();
    } catch (e) {
      if (mine === generation.current) setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function copyUrl(url: string) {
    try {
      await navigator.clipboard.writeText(url);
    } catch {
      // Clipboard access can be refused. The URL is a secret we refuse to put
      // on screen, so the honest fallback is the button that never needed it.
      setError("Could not copy the URL — use Open in browser instead.");
    }
  }

  // A detail belongs to a sandbox, so it is only this tab's while the names
  // agree: for the one commit between a switch and its answer, `detail` still
  // describes the sandbox we left, and rendering it there would hand out that
  // sandbox's password-bearing URL.
  const current = detail !== null && detail.name === name ? detail : null;
  const presentation = current === null ? null : vncPresentation(current);
  // The embed follows the LIVE desktop, not the config: a proxy is only worth
  // running while there is a URL to proxy.
  const liveUrl = presentation?.kind === "url" ? presentation.url : null;

  useEffect(() => {
    if (liveUrl === null) return;
    let dropped = false;
    setProxyError(null);
    void (async () => {
      try {
        const url = await api.vncProxyStart(name);
        if (!dropped) setProxyUrl(url);
      } catch (e) {
        // The embed is the loss; open-in-browser still reaches the desktop.
        if (!dropped) setProxyError(e instanceof Error ? e.message : String(e));
      }
    })();
    return () => {
      // Switching sandbox (or unmounting) must not leave a proxy behind, and a
      // late-arriving start must not paint the previous sandbox's frame.
      dropped = true;
      setProxyUrl(null);
      // Teardown has nowhere to report to — and a stop that fails must not
      // stop the next sandbox's embed from starting.
      void api.vncProxyStop(name).catch(() => {});
    };
  }, [name, liveUrl]);

  if (current === null || presentation === null) {
    return <div className="flex flex-col gap-4">{error && <ErrorLine text={error} />}</div>;
  }

  return (
    <div className="flex h-full flex-col gap-4">
      {error && <ErrorLine text={error} />}

      {presentation.kind === "not-enabled" && (
        <div className="flex flex-col items-start gap-3 text-sm">
          <div className="text-muted-foreground">
            Run a full Linux desktop in this sandbox, streamed to your browser.
          </div>
          <Button type="button" disabled={busy} onClick={() => void act(() => api.vncSet(name, true))}>
            Enable desktop
          </Button>
        </div>
      )}

      {presentation.kind === "not-running" && (
        <div className="flex flex-col items-start gap-3 text-sm">
          <div className="text-muted-foreground">
            The sandbox is stopped — start it to reach the desktop.
          </div>
          <Button type="button" disabled={busy} onClick={() => void act(() => api.start(name))}>
            Start
          </Button>
        </div>
      )}

      {presentation.kind === "restart-required" && (
        <div className="flex flex-col items-start gap-3">
          <RestartBanner name={name} busy={busy} act={act} />
          {/* `restart-required` is only reachable with `vnc: true` (see
              `vncPresentation`), so there is nothing to guard on here. */}
          <DisableButton name={name} busy={busy} act={act} />
        </div>
      )}

      {presentation.kind === "url" && (
        <>
          {presentation.warnings.map((w) => (
            <div key={w} className={BANNER}>
              <span>{w}</span>
            </div>
          ))}
          {/* Enabled, running, but booted with a different display config: the
              desktop on screen is not the one the config describes. */}
          {current.vnc_restart_required && current.vnc && (
            <RestartBanner name={name} busy={busy} act={act} />
          )}

          <div className="flex flex-wrap gap-1.5">
            <Button
              type="button"
              variant="secondary"
              size="sm"
              onClick={() => void openUrl(presentation.url)}
            >
              Open in browser
            </Button>
            <Button
              type="button"
              variant="secondary"
              size="sm"
              onClick={() => void copyUrl(presentation.url)}
            >
              Copy URL
            </Button>
            {current.vnc ? (
              <DisableButton name={name} busy={busy} act={act} />
            ) : (
              <Button
                type="button"
                variant="secondary"
                size="sm"
                disabled={busy}
                onClick={() => void act(() => api.vncSet(name, true))}
              >
                Enable desktop
              </Button>
            )}
          </div>

          {proxyError ? (
            <div className={BANNER}>
              <span>Could not embed the desktop: {proxyError}</span>
            </div>
          ) : (
            proxyUrl && (
              <iframe
                src={proxyUrl}
                title="Sandbox desktop"
                // min-h-96 (384px), not an arbitrary 480px: the lint gate bans
                // arbitrary values, and the frame grows to fill the tab anyway.
                className="min-h-96 w-full grow rounded-lg border"
              />
            )
          )}
        </>
      )}
    </div>
  );
}

function ErrorLine({ text }: Readonly<{ text: string }>) {
  return <div className="text-sm text-destructive">{text}</div>;
}

function RestartBanner({
  name,
  busy,
  act,
}: Readonly<{ name: string; busy: boolean; act: (fn: () => Promise<unknown>) => Promise<void> }>) {
  return (
    <div className={BANNER}>
      <span>Restart the sandbox to apply the desktop change.</span>
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
  );
}

function DisableButton({
  name,
  busy,
  act,
}: Readonly<{ name: string; busy: boolean; act: (fn: () => Promise<unknown>) => Promise<void> }>) {
  return (
    <Button
      type="button"
      variant="secondary"
      size="sm"
      disabled={busy}
      onClick={() => void act(() => api.vncSet(name, false))}
    >
      Disable desktop
    </Button>
  );
}
