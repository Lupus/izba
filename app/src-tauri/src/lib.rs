mod commands;
mod daemon;
#[cfg(test)]
mod fake;
mod views;

use std::sync::{Arc, Mutex};

use daemon::{DaemonApi, RealDaemon};
use tauri::{Emitter, State};
use views::{CreateOpts, DaemonStatusView, SandboxView, VersionView};

/// App-wide handle to izbad. `daemon` is the shared polling connection
/// (list/status). Slow/streaming actions use `make_daemon` to get their OWN
/// fresh connection inside `spawn_blocking`, so a boot-wait never blocks the
/// 2s poll (M1 carry-forward note).
pub struct AppState {
    pub daemon: Mutex<Box<dyn DaemonApi>>,
    pub make_daemon: Arc<dyn Fn() -> Box<dyn DaemonApi> + Send + Sync>,
}

#[tauri::command]
async fn list(state: State<'_, AppState>) -> Result<Vec<SandboxView>, String> {
    let mut guard = state
        .daemon
        .lock()
        .map_err(|e| format!("state poisoned: {e}"))?;
    commands::list_core(guard.as_mut())
}

#[tauri::command]
async fn daemon_status(state: State<'_, AppState>) -> Result<DaemonStatusView, String> {
    let mut guard = state
        .daemon
        .lock()
        .map_err(|e| format!("state poisoned: {e}"))?;
    commands::status_core(guard.as_mut())
}

#[tauri::command]
async fn version_info(state: State<'_, AppState>) -> Result<VersionView, String> {
    let mut guard = state
        .daemon
        .lock()
        .map_err(|e| format!("state poisoned: {e}"))?;
    commands::version_core(guard.as_mut())
}

/// Run a blocking action on a fresh daemon connection off the async runtime,
/// so a slow boot-wait never holds the shared polling lock.
async fn run_action<T, F>(state: &State<'_, AppState>, f: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce(&mut dyn DaemonApi) -> Result<T, String> + Send + 'static,
{
    let make = state.make_daemon.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let mut d = make();
        f(d.as_mut())
    })
    .await
    .map_err(|e| format!("task join error: {e}"))?
}

#[tauri::command]
async fn start(state: State<'_, AppState>, name: String) -> Result<(), String> {
    run_action(&state, move |d| commands::start_core(d, &name)).await
}

#[tauri::command]
async fn stop(state: State<'_, AppState>, name: String) -> Result<(), String> {
    run_action(&state, move |d| commands::stop_core(d, &name)).await
}

#[tauri::command]
async fn restart(state: State<'_, AppState>, name: String) -> Result<(), String> {
    run_action(&state, move |d| commands::restart_core(d, &name)).await
}

#[tauri::command]
async fn remove(state: State<'_, AppState>, name: String, force: bool) -> Result<(), String> {
    run_action(&state, move |d| commands::remove_core(d, &name, force)).await
}

#[tauri::command]
async fn create(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    opts: CreateOpts,
) -> Result<String, String> {
    run_action(&state, move |d| {
        commands::create_core(d, opts, &mut |m| {
            let _ = app.emit("create-progress", m.to_string());
        })
    })
    .await
}

#[tauri::command]
async fn read_logs(state: State<'_, AppState>, name: String) -> Result<String, String> {
    run_action(&state, move |d| commands::read_logs_core(d, &name)).await
}

pub fn run() {
    let state = AppState {
        daemon: Mutex::new(Box::new(RealDaemon::new())),
        make_daemon: Arc::new(|| Box::new(RealDaemon::new())),
    };
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            list,
            daemon_status,
            version_info,
            start,
            stop,
            restart,
            remove,
            create,
            read_logs
        ])
        .run(tauri::generate_context!())
        .expect("error while running izba app");
}
