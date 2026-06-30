//! Dogfood bridge sidecar: a single-client sync WebSocket server that drives
//! the real izba-app command/view/daemon layer (`app_lib::dispatch`) from a
//! browser. NOT shipped in the app; built only for GUI dogfooding.
//!
//! Protocol (text frames, JSON):
//!   client→  {"id":N,"cmd":"create","args":{...}}
//!   →client  {"type":"event","event":"create-progress","payload":"..."}   (0+)
//!   →client  {"id":N,"ok":true,"result":<json>}  |  {"id":N,"ok":false,"error":"..."}
//!
//! Port from $IZBA_DOGFOOD_WS_PORT (default 17890). IZBA_DATA_DIR selects the
//! daemon's data dir (RealDaemon::new reads it). Events are buffered during a
//! command and flushed before that command's reply — adequate for create
//! progress; live shell streaming is deferred (shell cmds return an error).
use std::collections::HashMap;
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use app_lib::{dispatch, AppState};

fn main() {
    let port: u16 = std::env::var("IZBA_DOGFOOD_WS_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(17890);
    let listener = TcpListener::bind(("127.0.0.1", port))
        .unwrap_or_else(|e| panic!("bind 127.0.0.1:{port}: {e}"));
    let state = AppState {
        daemon: Mutex::new(app_lib::new_real_daemon()),
        make_daemon: Arc::new(|| app_lib::new_real_daemon()),
        shells: Mutex::new(HashMap::new()),
    };
    // Single client (one browser). Re-accept on disconnect so a page reload
    // re-attaches.
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let mut ws = match tungstenite::accept(stream) {
            Ok(w) => w,
            Err(_) => continue,
        };
        loop {
            let msg = match ws.read() {
                Ok(m) => m,
                Err(_) => break,
            };
            if !msg.is_text() {
                continue;
            }
            let req: serde_json::Value = match serde_json::from_str(msg.to_text().unwrap_or("")) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let id = req.get("id").cloned().unwrap_or(serde_json::Value::Null);
            let cmd = req.get("cmd").and_then(|v| v.as_str()).unwrap_or("");
            let args = req.get("args").cloned().unwrap_or(serde_json::json!({}));

            let mut events: Vec<(String, serde_json::Value)> = Vec::new();
            let result = dispatch(&state, cmd, args, &mut |ev, payload| {
                events.push((ev.to_string(), payload));
            });
            // Flush events first, then the reply.
            for (ev, payload) in events {
                let frame = serde_json::json!({"type": "event", "event": ev, "payload": payload});
                let _ = ws.send(tungstenite::Message::Text(frame.to_string()));
            }
            let reply = match result {
                Ok(v) => serde_json::json!({"id": id, "ok": true, "result": v}),
                Err(e) => serde_json::json!({"id": id, "ok": false, "error": e}),
            };
            if ws
                .send(tungstenite::Message::Text(reply.to_string()))
                .is_err()
            {
                break;
            }
        }
    }
}
