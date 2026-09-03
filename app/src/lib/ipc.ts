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
  SeedEntry,
  GitRule,
  PortRule,
  VolumeInfo,
  SandboxDetail,
  DiffView,
  PromoteView,
  UsbUpstream,
  UsbDevice,
  UsbStatus,
  SandboxStats,
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
  policyRevoke: (name: string, host: string, port: number) =>
    invoke<void>("policy_revoke", { name, host, port }),
  policySet: (name: string, allow: AllowEntry[]) => invoke<void>("policy_set", { name, allow }),
  policyAddEndpoints: (name: string, entries: SeedEntry[], enforce: boolean) =>
    invoke<void>("policy_add_endpoints", { name, entries, enforce }),
  policySetFull: (name: string, allow: AllowEntry[], git: GitRule[]) =>
    invoke<void>("policy_set_full", { name, allow, git }),
  policySetEnforce: (name: string, on: boolean) =>
    invoke<void>("policy_set_enforce", { name, on }),
  // `target` is the raw glob string ("host/owner/repo" or "host"); the Rust
  // command parses it into a GitTarget. Sending a GitRule object would fail
  // Rust's `String` deserialization.
  policyGitAllow: (name: string, target: string, write: boolean) =>
    invoke<void>("policy_git_allow", { name, target, write }),
  policyGitRevoke: (name: string, target: string) =>
    invoke<void>("policy_git_revoke", { name, target }),
  inspect: (name: string) => invoke<SandboxDetail>("inspect", { name }),
  stats: (name: string) => invoke<SandboxStats>("stats", { name }),
  portList: (name: string) => invoke<PortRule[]>("port_list", { name }),
  portPublish: (name: string, rule: string, persist: boolean) =>
    invoke<void>("port_publish", { name, ruleSpec: rule, persist }),
  portUnpublish: (name: string, bind: string, hostPort: number) =>
    invoke<void>("port_unpublish", { name, bind, hostPort }),
  volumeList: () => invoke<VolumeInfo[]>("volume_list"),
  volumeRemove: (name: string) => invoke<void>("volume_remove", { name }),
  volumePrune: () => invoke<{ removed: string[]; reclaimed_bytes: number }>("volume_prune"),
  volumeAttach: (name: string, spec: string) => invoke<void>("volume_attach", { name, spec }),
  volumeDetach: (name: string, guestPath: string) =>
    invoke<void>("volume_detach", { name, guestPath }),
  // USB. `usbUpstreamShow` is the only one answerable while the feature is off;
  // every other call refuses, so callers gate on it rather than probing.
  usbUpstreamShow: () => invoke<UsbUpstream | null>("usb_upstream_show"),
  usbUpstreamSet: (host: string, port: number, allowRemote: boolean) =>
    invoke<void>("usb_upstream_set", { host, port, allowRemote }),
  usbListDevices: () => invoke<UsbDevice[]>("usb_list_devices"),
  usbStatus: (name: string) => invoke<UsbStatus>("usb_status", { name }),
  usbAllow: (name: string, device: string, busidPin: string | null) =>
    invoke<void>("usb_allow", { name, device, busidPin }),
  usbRevoke: (name: string, device: string) => invoke<void>("usb_revoke", { name, device }),
  usbAttach: (name: string, device: string) => invoke<void>("usb_attach", { name, device }),
  usbDetach: (name: string, device: string) => invoke<void>("usb_detach", { name, device }),
  manifestDiff: (name: string) => invoke<DiffView>("manifest_diff", { name }),
  manifestExport: (name: string) => invoke<string>("manifest_export", { name }),
  manifestPromote: (name: string, restart: boolean) =>
    invoke<PromoteView>("manifest_promote", { name, restart }),
  vncSet: (name: string, enabled: boolean) => invoke<void>("vnc_set", { name, enabled }),
  vncProxyStart: (name: string) => invoke<string>("vnc_proxy_start", { name }),
  vncProxyStop: (name: string) => invoke<void>("vnc_proxy_stop", { name }),
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
