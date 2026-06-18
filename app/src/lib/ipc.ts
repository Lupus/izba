import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  SandboxView,
  DaemonStatusView,
  VersionView,
  CreateOpts,
  ShellOutputPayload,
  ShellExitPayload,
  EndpointSummary,
  PolicyView,
  AllowEntry,
  GitRule,
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
  shellOpen: (name: string, id: string) => invoke<void>("shell_open", { name, id }),
  shellWrite: (id: string, data: string) => invoke<void>("shell_write", { id, data }),
  shellResize: (id: string, cols: number, rows: number) =>
    invoke<void>("shell_resize", { id, cols, rows }),
  shellClose: (id: string) => invoke<void>("shell_close", { id }),
  readNetlog: (name: string) => invoke<EndpointSummary[]>("read_netlog", { name }),
  policyShow: (name: string) => invoke<PolicyView>("policy_show", { name }),
  policyAllow: (name: string, host: string, port: number) =>
    invoke<void>("policy_allow", { name, host, port }),
  policyBlock: (name: string, host: string, port: number) =>
    invoke<void>("policy_block", { name, host, port }),
  policySet: (name: string, allow: AllowEntry[]) => invoke<void>("policy_set", { name, allow }),
  policyEnable: (name: string) => invoke<number>("policy_enable", { name }),
  policySetEnforce: (name: string, on: boolean) =>
    invoke<void>("policy_set_enforce", { name, on }),
  policyGitAllow: (name: string, target: GitRule, write: boolean) =>
    invoke<void>("policy_git_allow", { name, target, write }),
  policyGitBlock: (name: string, target: GitRule) =>
    invoke<void>("policy_git_block", { name, target }),
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
