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
use views::{
    CreateOpts, DaemonStatusView, DiffView, PortRuleView, SandboxDetailView, SandboxView,
    SeedEntry, VersionView, VolumeInfoView,
};

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
async fn policy_add_endpoints(
    state: State<'_, AppState>,
    name: String,
    entries: Vec<SeedEntry>,
    enforce: bool,
) -> Result<(), String> {
    run_action(&state, move |d| {
        commands::policy_add_endpoints_core(d, &name, entries, enforce)
    })
    .await
}

#[tauri::command]
async fn policy_set_full(
    state: State<'_, AppState>,
    name: String,
    allow: Vec<izba_core::daemon::egress::config::AllowEntry>,
    git: Vec<izba_core::daemon::egress::config::GitRule>,
) -> Result<(), String> {
    run_action(&state, move |d| {
        commands::policy_set_full_core(d, &name, allow, git)
    })
    .await
}

#[tauri::command]
async fn policy_git_allow(
    state: State<'_, AppState>,
    name: String,
    target: String,
    write: bool,
) -> Result<(), String> {
    run_action(&state, move |d| {
        commands::policy_git_allow_core(d, &name, &target, write)
    })
    .await
}

#[tauri::command]
async fn policy_git_block(
    state: State<'_, AppState>,
    name: String,
    target: String,
) -> Result<(), String> {
    run_action(&state, move |d| {
        commands::policy_git_block_core(d, &name, &target)
    })
    .await
}

#[tauri::command]
async fn policy_set_enforce(
    state: State<'_, AppState>,
    name: String,
    on: bool,
) -> Result<(), String> {
    run_action(&state, move |d| {
        commands::policy_set_enforce_core(d, &name, on)
    })
    .await
}

#[tauri::command]
async fn inspect(state: State<'_, AppState>, name: String) -> Result<SandboxDetailView, String> {
    run_action(&state, move |d| commands::inspect_core(d, &name)).await
}

#[tauri::command]
async fn port_list(state: State<'_, AppState>, name: String) -> Result<Vec<PortRuleView>, String> {
    run_action(&state, move |d| commands::port_list_core(d, &name)).await
}

#[tauri::command]
async fn port_publish(
    state: State<'_, AppState>,
    name: String,
    rule_spec: String,
    persist: bool,
) -> Result<(), String> {
    run_action(&state, move |d| {
        commands::port_publish_core(d, &name, &rule_spec, persist)
    })
    .await
}

#[tauri::command]
async fn port_unpublish(
    state: State<'_, AppState>,
    name: String,
    bind: std::net::Ipv4Addr,
    host_port: u16,
) -> Result<(), String> {
    run_action(&state, move |d| {
        commands::port_unpublish_core(d, &name, bind, host_port)
    })
    .await
}

#[tauri::command]
async fn volume_list(state: State<'_, AppState>) -> Result<Vec<VolumeInfoView>, String> {
    run_action(&state, move |d| commands::volume_list_core(d)).await
}

#[tauri::command]
async fn volume_remove(state: State<'_, AppState>, name: String) -> Result<(), String> {
    run_action(&state, move |d| commands::volume_remove_core(d, &name)).await
}

#[tauri::command]
async fn volume_prune(state: State<'_, AppState>) -> Result<izba_core::volume::Pruned, String> {
    run_action(&state, move |d| commands::volume_prune_core(d)).await
}

#[tauri::command]
async fn volume_attach(
    state: State<'_, AppState>,
    name: String,
    spec: String,
) -> Result<(), String> {
    run_action(&state, move |d| {
        commands::volume_attach_core(d, &name, &spec)
    })
    .await
}

#[tauri::command]
async fn volume_detach(
    state: State<'_, AppState>,
    name: String,
    guest_path: String,
) -> Result<(), String> {
    run_action(&state, move |d| {
        commands::volume_detach_core(d, &name, guest_path)
    })
    .await
}

#[tauri::command]
async fn manifest_diff(name: String) -> Result<DiffView, String> {
    tauri::async_runtime::spawn_blocking(move || commands::manifest_diff_core(&name))
        .await
        .map_err(|e| format!("task join error: {e}"))?
}

#[tauri::command]
async fn manifest_export(name: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || commands::manifest_export_core(&name))
        .await
        .map_err(|e| format!("task join error: {e}"))?
}

#[tauri::command]
async fn manifest_promote(name: String, restart: bool) -> Result<views::PromoteView, String> {
    tauri::async_runtime::spawn_blocking(move || commands::manifest_promote_core(&name, restart))
        .await
        .map_err(|e| format!("task join error: {e}"))?
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

/// Headless invoke dispatcher: the same command→core-fn mapping the
/// `#[tauri::command]` shims use, but transport-agnostic. Used by the dogfood
/// bridge sidecar (`bin/headless`) to drive the real command/view/daemon layer
/// from a browser without the Tauri runtime. `emit` carries Tauri events
/// (e.g. `create-progress`) back to the caller.
///
/// Shell commands are intentionally unsupported here (deferred — see the GUI
/// dogfooding spec §10); they return an explicit error rather than a stub.
pub fn dispatch(
    state: &AppState,
    cmd: &str,
    args: serde_json::Value,
    emit: &mut dyn FnMut(&str, serde_json::Value),
) -> Result<serde_json::Value, String> {
    use serde_json::json;

    fn arg_str(args: &serde_json::Value, key: &str) -> Result<String, String> {
        args.get(key)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| format!("missing string arg '{key}'"))
    }
    fn arg_u16(args: &serde_json::Value, key: &str) -> Result<u16, String> {
        args.get(key)
            .and_then(|v| v.as_u64())
            .and_then(|v| u16::try_from(v).ok())
            .ok_or_else(|| format!("missing u16 arg '{key}'"))
    }
    fn to_json<T: serde::Serialize>(v: T) -> Result<serde_json::Value, String> {
        serde_json::to_value(v).map_err(|e| format!("serialize error: {e}"))
    }

    let mut d = state
        .daemon
        .lock()
        .map_err(|e| format!("state poisoned: {e}"))?;
    let d = d.as_mut();
    match cmd {
        "list" => to_json(commands::list_core(d)?),
        "daemon_status" => to_json(commands::status_core(d)?),
        "version_info" => to_json(commands::version_core(d)?),
        "read_logs" => to_json(commands::read_logs_core(d, &arg_str(&args, "name")?)?),
        "start" => to_json(commands::start_core(d, &arg_str(&args, "name")?)?),
        "stop" => to_json(commands::stop_core(d, &arg_str(&args, "name")?)?),
        "restart" => to_json(commands::restart_core(d, &arg_str(&args, "name")?)?),
        "remove" => {
            let force = args.get("force").and_then(|v| v.as_bool()).unwrap_or(false);
            to_json(commands::remove_core(d, &arg_str(&args, "name")?, force)?)
        }
        "inspect" => to_json(commands::inspect_core(d, &arg_str(&args, "name")?)?),
        "read_netlog" => to_json(commands::read_netlog_core(d, &arg_str(&args, "name")?)?),
        "port_list" => to_json(commands::port_list_core(d, &arg_str(&args, "name")?)?),
        // NOTE on arg names: Tauri camelCases Rust snake_case command args in
        // invoke payloads, so the frontend (src/lib/ipc.ts) sends `ruleSpec`,
        // `hostPort`, and `guestPath` — the bridge must accept those exact
        // keys, not the Rust-side `rule_spec`/`host_port`/`guest_path`.
        "port_publish" => {
            let persist = args
                .get("persist")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            to_json(commands::port_publish_core(
                d,
                &arg_str(&args, "name")?,
                &arg_str(&args, "ruleSpec")?,
                persist,
            )?)
        }
        "port_unpublish" => {
            // `bind` arrives as a dotted-quad string (Ipv4Addr serializes as one).
            let bind: std::net::Ipv4Addr = arg_str(&args, "bind")?
                .parse()
                .map_err(|e| format!("bad bind: {e}"))?;
            to_json(commands::port_unpublish_core(
                d,
                &arg_str(&args, "name")?,
                bind,
                arg_u16(&args, "hostPort")?,
            )?)
        }
        "volume_list" => to_json(commands::volume_list_core(d)?),
        "volume_remove" => to_json(commands::volume_remove_core(d, &arg_str(&args, "name")?)?),
        "volume_prune" => to_json(commands::volume_prune_core(d)?),
        "volume_attach" => to_json(commands::volume_attach_core(
            d,
            &arg_str(&args, "name")?,
            &arg_str(&args, "spec")?,
        )?),
        "volume_detach" => to_json(commands::volume_detach_core(
            d,
            &arg_str(&args, "name")?,
            arg_str(&args, "guestPath")?,
        )?),
        "policy_show" => to_json(commands::policy_show_core(d, &arg_str(&args, "name")?)?),
        "policy_allow" => to_json(commands::policy_allow_core(
            d,
            &arg_str(&args, "name")?,
            &arg_str(&args, "host")?,
            arg_u16(&args, "port")?,
        )?),
        "policy_block" => to_json(commands::policy_block_core(
            d,
            &arg_str(&args, "name")?,
            &arg_str(&args, "host")?,
            arg_u16(&args, "port")?,
        )?),
        "policy_set" => {
            let allow: Vec<izba_core::daemon::egress::config::AllowEntry> = serde_json::from_value(
                args.get("allow")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
            )
            .map_err(|e| format!("bad allow: {e}"))?;
            to_json(commands::policy_set_core(
                d,
                &arg_str(&args, "name")?,
                allow,
            )?)
        }
        "policy_add_endpoints" => {
            let entries: Vec<SeedEntry> = serde_json::from_value(
                args.get("entries")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
            )
            .map_err(|e| format!("bad entries: {e}"))?;
            let enforce = args
                .get("enforce")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            to_json(commands::policy_add_endpoints_core(
                d,
                &arg_str(&args, "name")?,
                entries,
                enforce,
            )?)
        }
        // `target` is the raw glob string ("host/owner/repo" or "host") — the
        // core fn parses it into a GitTarget (mirrors src/lib/ipc.ts).
        "policy_git_allow" => {
            let write = args.get("write").and_then(|v| v.as_bool()).unwrap_or(false);
            to_json(commands::policy_git_allow_core(
                d,
                &arg_str(&args, "name")?,
                &arg_str(&args, "target")?,
                write,
            )?)
        }
        "policy_git_block" => to_json(commands::policy_git_block_core(
            d,
            &arg_str(&args, "name")?,
            &arg_str(&args, "target")?,
        )?),
        "policy_set_enforce" => {
            let on = args.get("on").and_then(|v| v.as_bool()).unwrap_or(false);
            to_json(commands::policy_set_enforce_core(
                d,
                &arg_str(&args, "name")?,
                on,
            )?)
        }
        "policy_set_full" => {
            let allow: Vec<izba_core::daemon::egress::config::AllowEntry> = serde_json::from_value(
                args.get("allow")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
            )
            .map_err(|e| format!("bad allow: {e}"))?;
            let git: Vec<izba_core::daemon::egress::config::GitRule> =
                serde_json::from_value(args.get("git").cloned().unwrap_or(serde_json::Value::Null))
                    .map_err(|e| format!("bad git: {e}"))?;
            to_json(commands::policy_set_full_core(
                d,
                &arg_str(&args, "name")?,
                allow,
                git,
            )?)
        }
        "create" => {
            let opts: views::CreateOpts = serde_json::from_value(
                args.get("opts").cloned().unwrap_or(serde_json::Value::Null),
            )
            .map_err(|e| format!("bad create opts: {e}"))?;
            let name = commands::create_core(d, opts, &mut |m| {
                emit("create-progress", json!(m));
            })?;
            to_json(name)
        }
        "shell_open" | "shell_write" | "shell_resize" | "shell_close" => {
            Err("shell not supported in dogfood headless (deferred)".to_string())
        }
        "manifest_diff" => to_json(commands::manifest_diff_core(&arg_str(&args, "name")?)?),
        "manifest_export" => to_json(commands::manifest_export_core(&arg_str(&args, "name")?)?),
        "manifest_promote" => {
            let restart = args
                .get("restart")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            to_json(commands::manifest_promote_core(
                &arg_str(&args, "name")?,
                restart,
            )?)
        }
        other => Err(format!("unknown command: {other}")),
    }
}

/// Constructor the dogfood bridge bin uses to build a real daemon connection.
pub fn new_real_daemon() -> Box<dyn DaemonApi> {
    Box::new(RealDaemon::new())
}

pub fn run() {
    let state = AppState {
        daemon: Mutex::new(Box::new(RealDaemon::new())),
        make_daemon: Arc::new(|| Box::new(RealDaemon::new())),
        shells: Mutex::new(HashMap::new()),
    };
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
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
            policy_add_endpoints,
            policy_set_full,
            policy_git_allow,
            policy_git_block,
            policy_set_enforce,
            inspect,
            port_list,
            port_publish,
            port_unpublish,
            volume_list,
            volume_remove,
            volume_prune,
            volume_attach,
            volume_detach,
            shell_open,
            shell_write,
            shell_resize,
            shell_close,
            manifest_diff,
            manifest_export,
            manifest_promote
        ])
        .run(tauri::generate_context!())
        .expect("error while running izba app");
}

#[cfg(test)]
mod dispatch_tests {
    use super::*;
    use crate::fake::FakeDaemon;
    use std::sync::{Arc, Mutex};

    fn state_with(d: FakeDaemon) -> AppState {
        AppState {
            daemon: Mutex::new(Box::new(d)),
            make_daemon: Arc::new(|| Box::new(FakeDaemon::default())),
            shells: Mutex::new(std::collections::HashMap::new()),
        }
    }

    #[test]
    fn dispatch_list_returns_sandbox_json() {
        let st = state_with(FakeDaemon::default());
        let mut emit = |_: &str, _: serde_json::Value| {};
        let out = dispatch(&st, "list", serde_json::json!({}), &mut emit).unwrap();
        assert!(out.is_array());
    }

    #[test]
    fn dispatch_volume_list_returns_volume_json() {
        // Regression: wandering Actors open the Storage view, whose
        // volume_list invoke previously had no dispatch arm and fell through
        // to "unknown command" — a false silent-failure finding against the
        // product, not a real bug.
        let st = state_with(FakeDaemon::default());
        let mut emit = |_: &str, _: serde_json::Value| {};
        let out = dispatch(&st, "volume_list", serde_json::json!({}), &mut emit).unwrap();
        assert!(out.is_array());
        assert_eq!(out.as_array().unwrap().len(), 1);
    }

    #[test]
    fn dispatch_unknown_cmd_errors() {
        let st = state_with(FakeDaemon::default());
        let mut emit = |_: &str, _: serde_json::Value| {};
        assert!(dispatch(&st, "no_such_cmd", serde_json::json!({}), &mut emit).is_err());
    }

    #[test]
    fn dispatch_shell_open_is_deferred_error() {
        let st = state_with(FakeDaemon::default());
        let mut emit = |_: &str, _: serde_json::Value| {};
        let e = dispatch(
            &st,
            "shell_open",
            serde_json::json!({"name": "a", "id": "s1"}),
            &mut emit,
        );
        assert!(e.is_err());
    }

    #[test]
    fn dispatch_policy_set_full_updates_policy() {
        // Regression: PolicyEditor's Save button invokes `policy_set_full`,
        // but the headless bridge had no matching dispatch arm — it fell
        // through to "unknown command", silently breaking Save in the
        // dogfood harness (and any journey depending on it).
        let st = state_with(FakeDaemon::default());
        let mut emit = |_: &str, _: serde_json::Value| {};
        let out = dispatch(
            &st,
            "policy_set_full",
            serde_json::json!({
                "name": "web",
                "allow": [{"host": "api.example.com", "ports": [443], "access": "read-write"}],
                "git": [{"host": "github.com", "access": "read"}],
            }),
            &mut emit,
        )
        .unwrap();
        assert!(out.is_null());

        let shown = dispatch(
            &st,
            "policy_show",
            serde_json::json!({"name": "web"}),
            &mut emit,
        )
        .unwrap();
        assert_eq!(shown["allow"][0]["host"], "api.example.com");
        assert_eq!(shown["git"][0]["host"], "github.com");
    }

    #[test]
    fn dispatch_manifest_diff_unknown_sandbox() {
        let st = state_with(FakeDaemon::default());
        let mut emit = |_: &str, _: serde_json::Value| {};
        let err = dispatch(
            &st,
            "manifest_diff",
            serde_json::json!({"name": "ghost"}),
            &mut emit,
        )
        .unwrap_err();
        assert!(err.contains("not found"), "got: {err}");
    }

    #[test]
    fn dispatch_manifest_export_unknown_sandbox() {
        let st = state_with(FakeDaemon::default());
        let mut emit = |_: &str, _: serde_json::Value| {};
        let err = dispatch(
            &st,
            "manifest_export",
            serde_json::json!({"name": "ghost"}),
            &mut emit,
        )
        .unwrap_err();
        assert!(err.contains("not found"), "got: {err}");
    }

    #[test]
    fn dispatch_port_publish_list_unpublish_round_trip() {
        // Payload shapes mirror src/lib/ipc.ts exactly: portPublish sends
        // `ruleSpec` and portUnpublish sends `hostPort` (Tauri camelCases the
        // Rust snake_case args in invoke payloads).
        let st = state_with(FakeDaemon::default());
        let mut emit = |_: &str, _: serde_json::Value| {};
        dispatch(
            &st,
            "port_publish",
            serde_json::json!({"name": "web", "ruleSpec": "127.0.0.1:8080:80", "persist": true}),
            &mut emit,
        )
        .unwrap();

        let listed = dispatch(
            &st,
            "port_list",
            serde_json::json!({"name": "web"}),
            &mut emit,
        )
        .unwrap();
        assert_eq!(listed[0]["bind"], "127.0.0.1");
        assert_eq!(listed[0]["host_port"], 8080);
        assert_eq!(listed[0]["guest_port"], 80);

        dispatch(
            &st,
            "port_unpublish",
            serde_json::json!({"name": "web", "bind": "127.0.0.1", "hostPort": 8080}),
            &mut emit,
        )
        .unwrap();
        let listed = dispatch(
            &st,
            "port_list",
            serde_json::json!({"name": "web"}),
            &mut emit,
        )
        .unwrap();
        assert_eq!(listed.as_array().unwrap().len(), 0);
    }

    #[test]
    fn dispatch_port_publish_rejects_snake_case_arg() {
        // Arg-shape guard: the frontend sends `ruleSpec` (camelCase); a
        // snake_case `rule_spec` payload is NOT what crosses the bridge and
        // must be rejected as a missing arg, not silently accepted.
        let st = state_with(FakeDaemon::default());
        let mut emit = |_: &str, _: serde_json::Value| {};
        let err = dispatch(
            &st,
            "port_publish",
            serde_json::json!({"name": "web", "rule_spec": "8080:80", "persist": false}),
            &mut emit,
        )
        .unwrap_err();
        assert!(err.contains("ruleSpec"), "got: {err}");
    }

    #[test]
    fn dispatch_volume_attach_detach_round_trip() {
        // volumeDetach sends `guestPath` (camelCase) per src/lib/ipc.ts.
        let st = state_with(FakeDaemon::default());
        let mut emit = |_: &str, _: serde_json::Value| {};
        dispatch(
            &st,
            "volume_attach",
            serde_json::json!({"name": "web", "spec": "cache:/data:1g"}),
            &mut emit,
        )
        .unwrap();
        let detail = dispatch(
            &st,
            "inspect",
            serde_json::json!({"name": "web"}),
            &mut emit,
        )
        .unwrap();
        assert_eq!(detail["volumes"][0]["guest_path"], "/data");

        dispatch(
            &st,
            "volume_detach",
            serde_json::json!({"name": "web", "guestPath": "/data"}),
            &mut emit,
        )
        .unwrap();
        let detail = dispatch(
            &st,
            "inspect",
            serde_json::json!({"name": "web"}),
            &mut emit,
        )
        .unwrap();
        assert_eq!(detail["volumes"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn dispatch_volume_remove_and_prune() {
        let st = state_with(FakeDaemon::default());
        let mut emit = |_: &str, _: serde_json::Value| {};
        let out = dispatch(
            &st,
            "volume_remove",
            serde_json::json!({"name": "cache"}),
            &mut emit,
        )
        .unwrap();
        assert!(out.is_null());
        let pruned = dispatch(&st, "volume_prune", serde_json::json!({}), &mut emit).unwrap();
        assert_eq!(pruned["removed"][0], "old");
        assert_eq!(pruned["reclaimed_bytes"], 1024);
    }

    #[test]
    fn dispatch_policy_allow_shows_up_in_policy_show() {
        let st = state_with(FakeDaemon::default());
        let mut emit = |_: &str, _: serde_json::Value| {};
        dispatch(
            &st,
            "policy_allow",
            serde_json::json!({"name": "web", "host": "pypi.org", "port": 443}),
            &mut emit,
        )
        .unwrap();
        let shown = dispatch(
            &st,
            "policy_show",
            serde_json::json!({"name": "web"}),
            &mut emit,
        )
        .unwrap();
        let hosts: Vec<&str> = shown["allow"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|e| e["host"].as_str())
            .collect();
        assert!(hosts.contains(&"pypi.org"), "got: {shown}");
    }

    #[test]
    fn dispatch_policy_block_and_set_accept_frontend_shapes() {
        let st = state_with(FakeDaemon::default());
        let mut emit = |_: &str, _: serde_json::Value| {};
        dispatch(
            &st,
            "policy_block",
            serde_json::json!({"name": "web", "host": "evil.example", "port": 443}),
            &mut emit,
        )
        .unwrap();
        dispatch(
            &st,
            "policy_set",
            serde_json::json!({
                "name": "web",
                "allow": [{"host": "api.example.com", "ports": [443], "access": "read-write"}],
            }),
            &mut emit,
        )
        .unwrap();
    }

    #[test]
    fn dispatch_policy_add_endpoints_then_show() {
        let st = state_with(FakeDaemon::default());
        let mut emit = |_: &str, _: serde_json::Value| {};
        dispatch(
            &st,
            "policy_add_endpoints",
            serde_json::json!({
                "name": "web",
                "entries": [{"kind": "http", "host": "crates.io", "port": 443, "access": "read"}],
                "enforce": true,
            }),
            &mut emit,
        )
        .unwrap();
        let shown = dispatch(
            &st,
            "policy_show",
            serde_json::json!({"name": "web"}),
            &mut emit,
        )
        .unwrap();
        assert_eq!(shown["enforcing"], true);
    }

    #[test]
    fn dispatch_policy_git_allow_block_round_trip() {
        // `target` is the raw glob string, exactly as ipc.ts sends it.
        let st = state_with(FakeDaemon::default());
        let mut emit = |_: &str, _: serde_json::Value| {};
        dispatch(
            &st,
            "policy_git_allow",
            serde_json::json!({"name": "web", "target": "github.com/o/r", "write": true}),
            &mut emit,
        )
        .unwrap();
        let shown = dispatch(
            &st,
            "policy_show",
            serde_json::json!({"name": "web"}),
            &mut emit,
        )
        .unwrap();
        assert_eq!(shown["git"].as_array().unwrap().len(), 1);

        dispatch(
            &st,
            "policy_git_block",
            serde_json::json!({"name": "web", "target": "github.com/o/r"}),
            &mut emit,
        )
        .unwrap();
        let shown = dispatch(
            &st,
            "policy_show",
            serde_json::json!({"name": "web"}),
            &mut emit,
        )
        .unwrap();
        assert_eq!(shown["git"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn dispatch_read_netlog_returns_summaries() {
        let st = state_with(FakeDaemon::default());
        let mut emit = |_: &str, _: serde_json::Value| {};
        let out = dispatch(
            &st,
            "read_netlog",
            serde_json::json!({"name": "web"}),
            &mut emit,
        )
        .unwrap();
        let rows = out.as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["host"], "api.x.com");
    }

    #[test]
    fn dispatch_manifest_promote_unknown_sandbox() {
        let st = state_with(FakeDaemon::default());
        let mut emit = |_: &str, _: serde_json::Value| {};
        let err = dispatch(
            &st,
            "manifest_promote",
            serde_json::json!({"name": "ghost", "restart": false}),
            &mut emit,
        )
        .unwrap_err();
        assert!(err.contains("not found"), "got: {err}");
    }
}
