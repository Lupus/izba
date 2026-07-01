// app/dogfood/real-bridge.js
// In-page Tauri bridge for GUI dogfooding. Same surface as e2e/mock/tauri-mock.js,
// but instead of canned scenario data it forwards invoke() over a WebSocket to
// the headless dogfood sidecar (app_lib::dispatch) and fires Tauri events from
// the sidecar back to the app. Also records uncaught errors and an invoke log
// for the dogfood oracles. Loaded as the FIRST <script> in the dogfood
// index.html so it defines __TAURI_INTERNALS__ before the app bundle runs.
(function () {
  // ---- pure protocol handler (also exported for unit tests) ----
  function __dfHandleMessage(state, raw) {
    var msg;
    try {
      msg = JSON.parse(raw);
    } catch {
      return;
    }
    if (msg && msg.type === "event") {
      var set = state.listeners.get(msg.event);
      if (set) {
        set.forEach(function (fn) {
          if (typeof fn === "function") fn({ event: msg.event, payload: msg.payload });
        });
      }
      return;
    }
    if (msg && typeof msg.id !== "undefined" && state.pending.has(msg.id)) {
      var p = state.pending.get(msg.id);
      state.pending.delete(msg.id);
      var cmd = state.lastCmd.get(msg.id) || "";
      state.lastCmd.delete(msg.id);
      if (msg.ok) {
        state.invokeLog.push({ cmd: cmd, ok: true, error: "" });
        p.resolve(msg.result);
      } else {
        state.invokeLog.push({ cmd: cmd, ok: false, error: String(msg.error || "") });
        p.reject(new Error(String(msg.error || "invoke failed")));
      }
    }
  }

  if (typeof module !== "undefined" && module) {
    module.exports = { __dfHandleMessage: __dfHandleMessage };
    if (typeof window === "undefined") return; // unit-test load: stop here
    if (typeof WebSocket === "undefined") return; // no real WS — skip browser install
  }

  // ---- browser install ----
  var win = window;
  win.__DF_CONSOLE_ERRORS__ = win.__DF_CONSOLE_ERRORS__ || [];
  win.__DF_INVOKE_LOG__ = win.__DF_INVOKE_LOG__ || [];
  win.addEventListener("error", function (e) {
    win.__DF_CONSOLE_ERRORS__.push(String((e && e.message) || e));
  });
  win.addEventListener("unhandledrejection", function (e) {
    win.__DF_CONSOLE_ERRORS__.push("unhandledrejection: " + String((e && e.reason) || e));
  });

  var state = {
    pending: new Map(),
    listeners: new Map(),
    invokeLog: win.__DF_INVOKE_LOG__,
    lastCmd: new Map(),
  };
  var nextId = 1;
  var queue = [];
  var ws = null;

  function wsPort() {
    var m = /[?&]ws=(\d+)/.exec(win.location.search || "");
    if (!m) return "17890";
    var p = parseInt(m[1], 10);
    return (p >= 1024 && p <= 65535) ? String(p) : "17890";
  }
  function connect() {
    ws = new WebSocket("ws://127.0.0.1:" + wsPort());
    ws.onmessage = function (ev) {
      __dfHandleMessage(state, ev.data);
    };
    ws.onopen = function () {
      queue.splice(0).forEach(function (f) {
        ws.send(f);
      });
    };
    ws.onclose = function () {
      setTimeout(connect, 300);
    };
  }
  connect();

  var internals = (win.__TAURI_INTERNALS__ = win.__TAURI_INTERNALS__ || {});
  internals.transformCallback = function (callback, once) {
    var id = win.crypto.getRandomValues(new Uint32Array(1))[0];
    var prop = "_" + id;
    Object.defineProperty(win, prop, {
      value: function (result) {
        if (once) Reflect.deleteProperty(win, prop);
        return callback && callback(result);
      },
      writable: false,
      configurable: true,
    });
    return id;
  };
  var eventInternals = (win.__TAURI_EVENT_PLUGIN_INTERNALS__ =
    win.__TAURI_EVENT_PLUGIN_INTERNALS__ || {});
  eventInternals.unregisterListener = function (event, id) {
    var set = state.listeners.get(event);
    if (set) set.forEach(function (h) { if (h.__id === id) set.delete(h); });
    Reflect.deleteProperty(win, "_" + id);
  };

  internals.invoke = function (cmd, args) {
    args = args || {};
    // Tauri's event plugin commands are handled in-page, not by the sidecar.
    if (cmd === "plugin:event|listen") {
      var set = state.listeners.get(args.event) || new Set();
      var handler = function (e) {
        var fn = win["_" + args.handler];
        if (typeof fn === "function") fn(e);
      };
      handler.__id = args.handler;
      set.add(handler);
      state.listeners.set(args.event, set);
      return Promise.resolve(args.handler);
    }
    if (cmd === "plugin:event|unlisten") {
      var s = state.listeners.get(args.event);
      if (s) s.forEach(function (h) { if (h.__id === args.eventId) s.delete(h); });
      return Promise.resolve();
    }
    if (cmd === "plugin:event|emit" || cmd === "plugin:event|emit_to") {
      return Promise.resolve();
    }
    // Real backend call.
    var id = nextId++;
    state.lastCmd.set(id, cmd);
    var frame = JSON.stringify({ id: id, cmd: cmd, args: args });
    var promise = new Promise(function (resolve, reject) {
      state.pending.set(id, { resolve: resolve, reject: reject });
    });
    if (ws && ws.readyState === 1) ws.send(frame);
    else queue.push(frame);
    return promise;
  };
})();
