import { useEffect, useState } from "react";
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

  async function load() {
    try {
      setDetail(await api.inspect(name));
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  useEffect(() => {
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

  async function copyUrl(url: string) {
    try {
      await navigator.clipboard.writeText(url);
    } catch {
      // Clipboard access can be refused. The URL is a secret we refuse to put
      // on screen, so the honest fallback is the button that never needed it.
      setError("Could not copy the URL — use Open in browser instead.");
    }
  }

  const presentation = detail === null ? null : vncPresentation(detail);
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

  if (detail === null || presentation === null) {
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
          {detail.vnc && <DisableButton name={name} busy={busy} act={act} />}
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
          {detail.vnc_restart_required && detail.vnc && (
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
            {detail.vnc ? (
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
