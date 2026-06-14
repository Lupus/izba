import { useEffect, useState } from "react";
import { api } from "../lib/ipc";
import type { BuildInfo, VersionView } from "../lib/types";

/** Short `0.1.0 (9f0d480)` summary for a build. */
function short(b: BuildInfo): string {
  const sha = b.git_sha && b.git_sha !== "unknown" ? b.git_sha.slice(0, 7) : "unknown";
  return `${b.pkg_version} (${sha})`;
}

function Row({ label, build }: { label: string; build: BuildInfo | null }) {
  return (
    <div className="flex justify-between gap-6 py-1 text-[13px]">
      <span className="text-ink-2">{label}</span>
      <span className="font-mono text-ink-1" title={build ? build.git_describe : undefined}>
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
        className="w-[360px] rounded-lg border border-line bg-surface p-5 shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-3 flex items-center justify-between">
          <h2 className="font-semibold">About izba</h2>
          <button
            className="text-ink-2 hover:text-ink-1"
            aria-label="Close"
            onClick={onClose}
          >
            ✕
          </button>
        </div>

        {error ? (
          <p className="text-[13px] text-warn">{error}</p>
        ) : !version ? (
          <p className="text-[13px] text-ink-2">Loading…</p>
        ) : (
          <>
            <Row label="App" build={version.app} />
            <Row label="Core" build={version.core} />
            <Row label="Daemon" build={version.daemon} />
            {version.mismatch && (
              <p className="mt-3 rounded-md bg-warn/10 px-2 py-1.5 text-[12px] text-warn">
                ⚠ app and daemon builds differ
              </p>
            )}
          </>
        )}
      </div>
    </div>
  );
}
