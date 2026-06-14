mod commands;
mod daemon;
#[cfg(test)]
mod fake;
mod views;

use std::sync::Mutex;

use daemon::{DaemonApi, RealDaemon};
use views::{DaemonStatusView, SandboxView, VersionView};

/// App-wide handle to izbad, guarded for the (blocking) DaemonClient.
pub struct AppState {
    pub daemon: Mutex<Box<dyn DaemonApi>>,
}

#[tauri::command]
async fn list(state: tauri::State<'_, AppState>) -> Result<Vec<SandboxView>, String> {
    let mut guard = state
        .daemon
        .lock()
        .map_err(|e| format!("state poisoned: {e}"))?;
    commands::list_core(guard.as_mut())
}

#[tauri::command]
async fn daemon_status(state: tauri::State<'_, AppState>) -> Result<DaemonStatusView, String> {
    let mut guard = state
        .daemon
        .lock()
        .map_err(|e| format!("state poisoned: {e}"))?;
    commands::status_core(guard.as_mut())
}

#[tauri::command]
async fn version_info(state: tauri::State<'_, AppState>) -> Result<VersionView, String> {
    let mut guard = state
        .daemon
        .lock()
        .map_err(|e| format!("state poisoned: {e}"))?;
    commands::version_core(guard.as_mut())
}

pub fn run() {
    let state = AppState {
        daemon: Mutex::new(Box::new(RealDaemon::new())),
    };
    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![list, daemon_status, version_info])
        .run(tauri::generate_context!())
        .expect("error while running izba app");
}
