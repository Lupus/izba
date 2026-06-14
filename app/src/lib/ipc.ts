import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type { SandboxView, DaemonStatusView, VersionView, CreateOpts } from "./types";

export const api = {
  list: () => invoke<SandboxView[]>("list"),
  daemonStatus: () => invoke<DaemonStatusView>("daemon_status"),
  versionInfo: () => invoke<VersionView>("version_info"),
  start: (name: string) => invoke<void>("start", { name }),
  stop: (name: string) => invoke<void>("stop", { name }),
  restart: (name: string) => invoke<void>("restart", { name }),
  remove: (name: string, force: boolean) => invoke<void>("remove", { name, force }),
  create: (opts: CreateOpts) => invoke<string>("create", { opts }),
};

/** Subscribe to streamed create-progress messages. Returns an unlisten fn. */
export function onCreateProgress(cb: (msg: string) => void): Promise<UnlistenFn> {
  return listen<string>("create-progress", (e) => cb(e.payload));
}
