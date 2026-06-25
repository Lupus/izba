import { useEffect, useState } from "react";
import { api } from "../lib/ipc";
import type { BuildInfo, VersionView } from "../lib/types";
import { Button } from "@/components/ui/button";

/** Short `0.1.0 (9f0d480)` summary for a build. */
function short(b: BuildInfo): string {
  const sha = b.git_sha && b.git_sha !== "unknown" ? b.git_sha.slice(0, 7) : "unknown";
  return `${b.pkg_version} (${sha})`;
}

function Row({ label, build }: { label: string; build: BuildInfo | null }) {
  return (
    <div className="flex justify-between gap-6 py-1 text-sm">
      <span className="text-muted-foreground">{label}</span>
      <span className="font-mono text-foreground" title={build ? build.git_describe : undefined}>
        {build ? short(build) : "not running"}
      </span>
    </div>
  );
}

/** Modal About panel: app / core / daemon builds with a mismatch warning. */
export function About({ onClose }: { onClose: () => void }) {
  const [version, setVersion] = useState<VersionView | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    api
      .versionInfo()
      .then((v) => alive && setVersion(v))
      .catch((e) => alive && setError(e instanceof Error ? e.message : String(e)));
    return () => {
      alive = false;
    };
  }, []);

  return (
    <div
      className="fixed inset-0 z-50 grid place-items-center bg-black/30"
      role="dialog"
      aria-modal="true"
      aria-label="About izba"
      onClick={onClose}
    >
      <div
        className="w-80 rounded-lg border border-border bg-card p-5 shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-3 flex items-center justify-between">
          <h2 className="font-semibold">About izba</h2>
          <Button
            variant="ghost"
            size="icon"
            aria-label="Close"
            onClick={onClose}
          >
            ✕
          </Button>
        </div>

        {error ? (
          <p className="text-sm text-destructive">{error}</p>
        ) : !version ? (
          <p className="text-sm text-muted-foreground">Loading…</p>
        ) : (
          <>
            <Row label="App" build={version.app} />
            <Row label="Core" build={version.core} />
            <Row label="Daemon" build={version.daemon} />
            {version.mismatch && (
              <p className="mt-3 rounded-md bg-destructive/10 px-2 py-1.5 text-xs text-destructive">
                ⚠ app and daemon builds differ
              </p>
            )}
          </>
        )}
      </div>
    </div>
  );
}
