import { invoke } from "@tauri-apps/api/core";
import type { SandboxView, DaemonStatusView } from "./types";

export const api = {
  list: () => invoke<SandboxView[]>("list"),
  daemonStatus: () => invoke<DaemonStatusView>("daemon_status"),
};
