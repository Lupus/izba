// Self-contained in-page Tauri IPC mock for Playwright e2e.
// Injected via page.addInitScript({ path }) AFTER the scenario init script, so
// it runs BEFORE the app bundle. Reimplements @tauri-apps/api/mocks `mockIPC`
// (overwriting __TAURI_INTERNALS__.invoke + transformCallback), adds an
// event-listener registry, and a command dispatcher driven by
// window.__IZBA_SCENARIO__. Exposes window.__IZBA_MOCK__ for the test side.
(function () {
  const internals = (window.__TAURI_INTERNALS__ = window.__TAURI_INTERNALS__ || {});

  // transformCallback: exact behaviour from @tauri-apps/api mocks.ts — register
  // the handler as a global `window._<id>` and return its numeric id.
  internals.transformCallback = function (callback, once) {
    const id = window.crypto.getRandomValues(new Uint32Array(1))[0];
    const prop = "_" + id;
    Object.defineProperty(window, prop, {
      value: function (result) {
        if (once) Reflect.deleteProperty(window, prop);
        return callback && callback(result);
      },
      writable: false,
      configurable: true,
    });
    return id;
  };

  const scenario = window.__IZBA_SCENARIO__ || {};
  const calls = [];
  const listeners = new Map(); // event name -> Set<handler id>
  let deferredCreate = null;

  // Canned manifest_diff/manifest_export/manifest_promote responses, overridable
  // per-test via window.__MOCK_MANIFEST__ = { diff, export, promote, promoteError }.
  // promoteError, when set, makes manifest_promote reject with that message
  // instead of resolving `promote` — used to exercise ManifestTab's
  // mapPromoteError() copy mapping for the backend's raw CLI-speak errors.
  const DEFAULT_MANIFEST_DELTA = {
    field: "policy.egress.enforce",
    from: "true",
    to: "false",
    class: "live",
    weakens_egress: true,
  };
  const DEFAULT_MANIFEST_DIFF = { state: "repo_ahead", deltas: [DEFAULT_MANIFEST_DELTA] };
  const DEFAULT_MANIFEST_EXPORT = "/ws/izba.yml";
  const DEFAULT_MANIFEST_PROMOTE = {
    state: "in_sync",
    applied: [DEFAULT_MANIFEST_DELTA],
    needs_restart: false,
    restarted: false,
    stopped: false,
    warnings: ["promote: ⚠ weakens egress"],
  };

  // The event module's unlisten() calls
  // __TAURI_EVENT_PLUGIN_INTERNALS__.unregisterListener(event, id) BEFORE the
  // `plugin:event|unlisten` invoke (see @tauri-apps/api/event.js), so the real
  // mocks.js defines it too. Without it every unlisten throws (e.g. NewSandbox
  // dialog cleanup). Drop both the global handler and the registry entry.
  const eventInternals = (window.__TAURI_EVENT_PLUGIN_INTERNALS__ =
    window.__TAURI_EVENT_PLUGIN_INTERNALS__ || {});
  eventInternals.unregisterListener = function (event, id) {
    const set = listeners.get(event);
    if (set) set.delete(id);
    Reflect.deleteProperty(window, "_" + id);
  };

  function err(msg) {
    return Promise.reject(new Error(msg));
  }
  function action() {
    return scenario.failAction
      ? err(scenario.errorMessage || "action failed")
      : Promise.resolve();
  }
  function fireEvent(event, payload) {
    const ids = listeners.get(event);
    if (!ids) return 0;
    let n = 0;
    ids.forEach(function (id) {
      const fn = window["_" + id];
      if (typeof fn === "function") {
        fn({ event: event, id: id, payload: payload });
        n++;
      }
    });
    return n;
  }

  internals.invoke = function (cmd, args) {
    args = args || {};
    switch (cmd) {
      case "plugin:event|listen": {
        const set = listeners.get(args.event) || new Set();
        set.add(args.handler);
        listeners.set(args.event, set);
        return Promise.resolve(args.handler);
      }
      case "plugin:event|unlisten": {
        const set = listeners.get(args.event);
        if (set) set.delete(args.eventId);
        return Promise.resolve();
      }
      case "plugin:event|emit":
      case "plugin:event|emit_to":
        return Promise.resolve();

      case "list":
        return scenario.daemonAbsent || scenario.failList
          ? err(scenario.errorMessage || "daemon unreachable")
          : Promise.resolve(scenario.sandboxes || []);
      case "daemon_status":
        return scenario.daemonAbsent || scenario.failStatus
          ? err(scenario.errorMessage || "daemon unreachable")
          : Promise.resolve(scenario.daemonStatus);
      case "version_info":
        return Promise.resolve(scenario.version);

      case "start":
        calls.push("start:" + args.name);
        return action();
      case "stop":
        calls.push("stop:" + args.name);
        return action();
      case "restart":
        calls.push("restart:" + args.name);
        return action();
      case "remove":
        calls.push("remove:" + args.name + ":" + args.force);
        return action();

      case "create": {
        calls.push("create:" + (args.opts && args.opts.name));
        window.__IZBA_LAST_CREATE__ = args.opts;
        if (scenario.createDeferred)
          return new Promise(function (resolve, reject) {
            deferredCreate = { resolve: resolve, reject: reject };
          });
        if (scenario.createError) return err(scenario.createError);
        return Promise.resolve(scenario.createName || (args.opts && args.opts.name));
      }

      case "read_logs":
        calls.push("read_logs:" + args.name);
        return Promise.resolve(scenario.logs || "");
      case "read_netlog":
        calls.push("read_netlog:" + args.name);
        return Promise.resolve(scenario.netlog || []);

      case "policy_show":
        calls.push("policy_show:" + args.name);
        return Promise.resolve(
          (scenario.policy && scenario.policy[args.name]) || {
            enforcing: false,
            allow: [],
            git: [],
          }
        );
      case "policy_allow":
        calls.push("policy_allow:" + args.name + ":" + args.host + ":" + args.port);
        return action();
      case "policy_block":
        calls.push("policy_block:" + args.name + ":" + args.host + ":" + args.port);
        return action();
      case "policy_set":
        calls.push("policy_set:" + args.name);
        return action();
      case "policy_enable":
        calls.push("policy_enable:" + args.name);
        return scenario.failAction
          ? err(scenario.errorMessage || "action failed")
          : Promise.resolve(scenario.policyEnableCount || 0);

      case "shell_open":
        calls.push("shell_open:" + args.name + ":" + args.id);
        return action();
      case "shell_write":
        calls.push("shell_write:" + args.id + ":" + args.data);
        return action();
      case "shell_resize":
        calls.push("shell_resize:" + args.id + ":" + args.cols + "x" + args.rows);
        return action();
      case "shell_close":
        calls.push("shell_close:" + args.id);
        return action();

      // Manifest diff/export/promote. Canned defaults below; specs override
      // per-call via window.__MOCK_MANIFEST__ = { diff, export, promote }
      // (read live here, not captured at init, so a spec can set it after
      // the page has loaded but before triggering the invoke).
      case "manifest_diff":
        calls.push("manifest_diff:" + args.name);
        return Promise.resolve(
          (window.__MOCK_MANIFEST__ && window.__MOCK_MANIFEST__.diff) || DEFAULT_MANIFEST_DIFF
        );
      case "manifest_export":
        calls.push("manifest_export:" + args.name);
        return Promise.resolve(
          (window.__MOCK_MANIFEST__ && window.__MOCK_MANIFEST__.export) ||
            DEFAULT_MANIFEST_EXPORT
        );
      case "manifest_promote":
        calls.push("manifest_promote:" + args.name + ":" + args.restart);
        if (window.__MOCK_MANIFEST__ && window.__MOCK_MANIFEST__.promoteError) {
          return err(window.__MOCK_MANIFEST__.promoteError);
        }
        return Promise.resolve(
          (window.__MOCK_MANIFEST__ && window.__MOCK_MANIFEST__.promote) ||
            DEFAULT_MANIFEST_PROMOTE
        );

      default:
        return err("unmocked command: " + cmd);
    }
  };

  window.__IZBA_MOCK__ = {
    calls: function () {
      return calls.slice();
    },
    lastCreate: function () {
      return window.__IZBA_LAST_CREATE__;
    },
    fireEvent: fireEvent,
    pushCreateProgress: function (msg) {
      // `void` makes the discard explicit: these helpers are typed `void` in
      // helpers.ts, so callers must not depend on fireEvent's listener count.
      void fireEvent("create-progress", msg);
    },
    pushShellOutput: function (id, text) {
      // btoa handles ASCII test strings; that is all the specs use.
      void fireEvent("shell-output", { id: id, data: btoa(text) });
    },
    fireShellExit: function (id) {
      void fireEvent("shell-exit", { id: id });
    },
    resolveCreate: function (name) {
      if (deferredCreate) deferredCreate.resolve(name);
    },
    rejectCreate: function (msg) {
      if (deferredCreate) deferredCreate.reject(new Error(msg));
    },
    setScenario: function (partial) {
      Object.assign(scenario, partial);
    },
  };
})();
