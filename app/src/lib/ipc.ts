import { invoke } from "@tauri-apps/api/core";
import type { SandboxView, DaemonStatusView, VersionView } from "./types";

export const api = {
  list: () => invoke<SandboxView[]>("list"),
  daemonStatus: () => invoke<DaemonStatusView>("daemon_status"),
  versionInfo: () => invoke<VersionView>("version_info"),
};
