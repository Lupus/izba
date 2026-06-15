mod commands;
mod daemon;
#[cfg(test)]
mod fake;
mod views;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use daemon::{DaemonApi, RealDaemon, ShellSession};
use tauri::{Emitter, State};
use views::{CreateOpts, DaemonStatusView, SandboxView, VersionView};

/// A live interactive shell, wrapped so the `shells` map lock is only held for
/// the lookup — the per-session lock is what guards (blocking) shell I/O.
type ShellHandle = Arc<Mutex<Box<dyn ShellSession>>>;

/// App-wide handle to izbad. `daemon` is the shared polling connection
/// (list/status). Slow/streaming actions use `make_daemon` to get their OWN
/// fresh connection inside `spawn_blocking`, so a boot-wait never blocks the
/// 2s poll (M1 carry-forward note).
pub struct AppState {
    pub daemon: Mutex<Box<dyn DaemonApi>>,
    pub make_daemon: Arc<dyn Fn() -> Box<dyn DaemonApi> + Send + Sync>,
    /// Live interactive shells, keyed by session id now.
    pub shells: Mutex<HashMap<String, ShellHandle>>,
}

/// Look up a live shell, cloning the per-session handle so the map lock is
/// released before any (blocking) shell I/O runs.
fn shell_handle(state: &AppState, id: &str) -> Result<ShellHandle, String> {
    let shells = state
        .shells
        .lock()
        .map_err(|e| format!("state poisoned: {e}"))?;
    shells
        .get(id)
        .cloned()
        .ok_or_else(|| "no active shell".to_string())
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

#[tauri::command]
async fn read_netlog(
    state: State<'_, AppState>,
    name: String,
) -> Result<Vec<izba_core::daemon::egress::audit::EndpointSummary>, String> {
    run_action(&state, move |d| commands::read_netlog_core(d, &name)).await
}

#[tauri::command]
async fn policy_show(
    state: State<'_, AppState>,
    name: String,
) -> Result<views::PolicyView, String> {
    run_action(&state, move |d| commands::policy_show_core(d, &name)).await
}

#[tauri::command]
async fn policy_allow(
    state: State<'_, AppState>,
    name: String,
    host: String,
    port: u16,
) -> Result<(), String> {
    run_action(&state, move |d| {
        commands::policy_allow_core(d, &name, &host, port)
    })
    .await
}

#[tauri::command]
async fn policy_block(
    state: State<'_, AppState>,
    name: String,
    host: String,
    port: u16,
) -> Result<(), String> {
    run_action(&state, move |d| {
        commands::policy_block_core(d, &name, &host, port)
    })
    .await
}

#[tauri::command]
async fn policy_set(
    state: State<'_, AppState>,
    name: String,
    allow: Vec<izba_core::daemon::egress::config::AllowEntry>,
) -> Result<(), String> {
    run_action(&state, move |d| commands::policy_set_core(d, &name, allow)).await
}

#[tauri::command]
async fn policy_enable(state: State<'_, AppState>, name: String) -> Result<usize, String> {
    run_action(&state, move |d| commands::policy_enable_core(d, &name)).await
}

#[derive(Clone, serde::Serialize)]
struct ShellOutput {
    id: String,
    /// Base64-encoded raw PTY bytes (terminal output is not always UTF-8).
    data: String,
}

#[derive(Clone, serde::Serialize)]
struct ShellExit {
    id: String,
}

#[tauri::command]
async fn shell_open(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    name: String,
    id: String,
) -> Result<(), String> {
    // The frontend mints the id (subscribes to its events BEFORE this call so
    // no early output is lost). Reject a clash so we never clobber a live session.
    {
        let shells = state
            .shells
            .lock()
            .map_err(|e| format!("state poisoned: {e}"))?;
        if shells.contains_key(&id) {
            return Err("shell id already in use".to_string());
        }
    }
    let make = state.make_daemon.clone();
    let out_app = app.clone();
    let out_id = id.clone();
    let exit_app = app.clone();
    let exit_id = id.clone();
    let session = tauri::async_runtime::spawn_blocking(move || {
        let mut d = make();
        d.open_shell(
            &name,
            Box::new(move |bytes: Vec<u8>| {
                let data = base64::engine::general_purpose::STANDARD.encode(&bytes);
                let _ = out_app.emit(
                    "shell-output",
                    ShellOutput {
                        id: out_id.clone(),
                        data,
                    },
                );
            }),
            Box::new(move || {
                let _ = exit_app.emit("shell-exit", ShellExit { id: exit_id });
            }),
        )
    })
    .await
    .map_err(|e| format!("task join error: {e}"))?
    .map_err(|e| e.to_string())?;
    state
        .shells
        .lock()
        .map_err(|e| format!("state poisoned: {e}"))?
        .insert(id, Arc::new(Mutex::new(session)));
    Ok(())
}

#[tauri::command]
async fn shell_write(state: State<'_, AppState>, id: String, data: String) -> Result<(), String> {
    let shell = shell_handle(&state, &id)?;
    let mut s = shell.lock().map_err(|e| format!("shell poisoned: {e}"))?;
    s.write(data.as_bytes()).map_err(|e| e.to_string())
}

#[tauri::command]
async fn shell_resize(
    state: State<'_, AppState>,
    id: String,
    cols: u16,
    rows: u16,
) -> Result<(), String> {
    let shell = shell_handle(&state, &id)?;
    let mut s = shell.lock().map_err(|e| format!("shell poisoned: {e}"))?;
    s.resize(cols, rows).map_err(|e| e.to_string())
}

#[tauri::command]
async fn shell_close(state: State<'_, AppState>, id: String) -> Result<(), String> {
    let shell = {
        let mut shells = state
            .shells
            .lock()
            .map_err(|e| format!("state poisoned: {e}"))?;
        shells.remove(&id)
    };
    if let Some(shell) = shell {
        let mut s = shell.lock().map_err(|e| format!("shell poisoned: {e}"))?;
        s.close().map_err(|e| e.to_string())?;
    }
    Ok(())
}

pub fn run() {
    let state = AppState {
        daemon: Mutex::new(Box::new(RealDaemon::new())),
        make_daemon: Arc::new(|| Box::new(RealDaemon::new())),
        shells: Mutex::new(HashMap::new()),
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
            read_logs,
            read_netlog,
            policy_show,
            policy_allow,
            policy_block,
            policy_set,
            policy_enable,
            shell_open,
            shell_write,
            shell_resize,
            shell_close
        ])
        .run(tauri::generate_context!())
        .expect("error while running izba app");
}
