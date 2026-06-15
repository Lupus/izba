import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  SandboxView,
  DaemonStatusView,
  VersionView,
  CreateOpts,
  ShellOutputPayload,
  ShellExitPayload,
} from "./types";

export const api = {
  list: () => invoke<SandboxView[]>("list"),
  daemonStatus: () => invoke<DaemonStatusView>("daemon_status"),
  versionInfo: () => invoke<VersionView>("version_info"),
  start: (name: string) => invoke<void>("start", { name }),
  stop: (name: string) => invoke<void>("stop", { name }),
  restart: (name: string) => invoke<void>("restart", { name }),
  remove: (name: string, force: boolean) => invoke<void>("remove", { name, force }),
  create: (opts: CreateOpts) => invoke<string>("create", { opts }),
  readLogs: (name: string) => invoke<string>("read_logs", { name }),
  shellOpen: (name: string) => invoke<string>("shell_open", { name }), // returns session id
  shellWrite: (id: string, data: string) => invoke<void>("shell_write", { id, data }),
  shellResize: (id: string, cols: number, rows: number) =>
    invoke<void>("shell_resize", { id, cols, rows }),
  shellClose: (id: string) => invoke<void>("shell_close", { id }),
};

/** Decode a base64 string to raw bytes (xterm.write accepts Uint8Array). */
export function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Subscribe to streamed create-progress messages. Returns an unlisten fn. */
export function onCreateProgress(cb: (msg: string) => void): Promise<UnlistenFn> {
  return listen<string>("create-progress", (e) => cb(e.payload));
}

/** Subscribe to a shell session's output (decoded to bytes), filtered by id. */
export function onShellOutput(id: string, cb: (bytes: Uint8Array) => void): Promise<UnlistenFn> {
  return listen<ShellOutputPayload>("shell-output", (e) => {
    if (e.payload.id === id) cb(b64ToBytes(e.payload.data));
  });
}

/** Subscribe to a shell session's exit, filtered by id. */
export function onShellExit(id: string, cb: () => void): Promise<UnlistenFn> {
  return listen<ShellExitPayload>("shell-exit", (e) => {
    if (e.payload.id === id) cb();
  });
}
