# Policy Validation & Error UX Bugfix Sprint Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One PR fixing four clustered issues on the egress-policy surface: #138 (unknown YAML keys silently accepted → permissive fallback), #83 (opaque raw-serde parse errors), #139 (failed `create --policy <missing file>` leaves a stub sandbox registered), #82 (policy mutating verbs leak a raw OS error for an unknown sandbox).

**Architecture:** Replace the derived-serde `from_yaml` path with a manual, strict walk over `serde_yaml::Value` (the schema's untagged `AllowEntry` and flattened `GitRule` make `#[serde(deny_unknown_fields)]` inert), producing errors that name the offending field path and its valid keys. Move `--policy` file read+validation *before* the daemon `Create` RPC so a bad file can never leave a stub sandbox. Add the existing `no such sandbox` guard to the five mutating policy verbs. Surface policy parse errors from the daemon `ReloadPolicy` handler instead of silently arming deny-all.

**Tech Stack:** Rust workspace (`izba-core`, `izba-cli`), serde_yaml 0.9, anyhow, tempfile-based unit tests, `env!("CARGO_BIN_EXE_izba")` binary-invocation integration tests (no KVM/daemon needed).

## Global Constraints

- All six workspace gates must be green before any commit (`CLAUDE.md` "Build & test"): `cargo test --workspace`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo fmt --check`; `cargo build -p izba-init --target x86_64-unknown-linux-musl --release`; `cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli`; `cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings`. For per-task commits, running the targeted crate tests + fmt + clippy is acceptable; the FULL six gates run in the final task before push.
- `[ -f .cargo-env ] && source .cargo-env` before any cargo command.
- Conventional commits (`fix(core): ...`). Never `git add -A` — stage exact files.
- Unit tests never bind unix/vsock listeners.
- Failure-mode decision (locked, per issue #138 INVEST note + the project's "loud on security degradation" principle): unknown keys are a **hard error**, not a warning. The daemon-side `resolve_policy` already fails CLOSED (deny-all) on parse errors, so a pre-existing on-disk file with a stray key degrades to deny-all + logged error — never silently permissive.
- Out of scope (locked by the issues): the `izba.yml` manifest deserialization path (`manifest/schema.rs`, `SandboxSpec.egress`) keeps derived serde behavior; `show`/`enable` guards already exist and their behavior must not change; multi-error reporting (first clear error is enough).
- The derived `Deserialize`/`Serialize` impls on `Access`/`AllowEntry`/`GitRule`/`GitTarget`/`EgressPolicyConfig` **stay** (the manifest path and `to_yaml` need them); only `from_yaml` switches to the manual walk. `RawConfig` is deleted.

## File Structure

- `crates/izba-core/src/daemon/egress/config.rs` — strict manual `from_yaml` + helpers + new unit tests (Task 2).
- `crates/izba-core/src/daemon/server.rs` — `ReloadPolicy` pre-validation (Task 3).
- `crates/izba-cli/src/commands/policy.rs` — `require_sandbox_dir` guard + tests (Task 1).
- `crates/izba-cli/src/commands/mod.rs` — `persist_policy` split into `read_policy` + `write_policy` (Task 4).
- `crates/izba-cli/src/commands/create.rs`, `crates/izba-cli/src/commands/run.rs` — reorder validation before the Create RPC (Task 4).
- `crates/izba-cli/tests/create_policy_failures.rs` — new binary-level integration tests (Task 5).
- `README.md` — one-line note that unknown policy keys are rejected (Task 2).

---

### Task 1: `no such sandbox` guard for the five mutating policy verbs (#82)

**Files:**
- Modify: `crates/izba-cli/src/commands/policy.rs` (dispatcher arms ~`policy.rs:88-139`, `show` ~172, `enable` ~215; tests mod at end)

**Interfaces:**
- Produces: private `fn require_sandbox_dir(paths: &Paths, name: &str) -> anyhow::Result<std::path::PathBuf>` used by all policy verbs. No cross-task consumers.

- [ ] **Step 1: Write the failing test** — append to the existing `mod tests` in `policy.rs`:

```rust
#[test]
fn mutating_verbs_bail_cleanly_on_unknown_sandbox() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = Paths::with_root(tmp.path().to_path_buf());
    let cases: Vec<PolicyCmd> = vec![
        PolicyCmd::Allow { name: "ghost".into(), target: "example.com".into() },
        PolicyCmd::Block { name: "ghost".into(), target: "example.com".into() },
        PolicyCmd::Enforce { name: "ghost".into(), state: EnforceState::On },
        PolicyCmd::Git(GitSub::Allow {
            name: "ghost".into(),
            target: "github.com/foo/bar".into(),
            write: false,
        }),
        PolicyCmd::Git(GitSub::Block { name: "ghost".into(), target: "github.com".into() }),
    ];
    for cmd in cases {
        let err = run(&paths, &cmd).expect_err("unknown sandbox must fail");
        let msg = format!("{err:#}");
        assert_eq!(msg, "no such sandbox: ghost", "cmd {cmd:?} leaked: {msg}");
    }
    // The failed verbs must not have created any stub state.
    assert!(!paths.sandbox_dir("ghost").exists());
}
```

(Adapt the `Paths` constructor to whatever the existing tests in `commands/mod.rs` use — they use `Paths::with_root`. If `PolicyCmd` doesn't derive `Debug` for the assert message, it does — see `#[derive(Debug, Subcommand)]`.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p izba-cli mutating_verbs_bail_cleanly -- --nocapture`
Expected: FAIL — the error message is the raw `writing .../sandboxes/ghost/policy.yaml: No such file or directory (os error 2)`, not `no such sandbox: ghost`.

- [ ] **Step 3: Implement the guard** — add near `parse_target` in `policy.rs`:

```rust
/// Every policy verb addresses an existing sandbox. Fail with a clean domain
/// error — not a raw ENOENT that leaks the data-dir path — when it doesn't
/// exist (#82). Mirrors the guard `show`/`enable` already had.
fn require_sandbox_dir(paths: &Paths, name: &str) -> anyhow::Result<std::path::PathBuf> {
    let dir = paths.sandbox_dir(name);
    if !dir.exists() {
        anyhow::bail!("no such sandbox: {name}");
    }
    Ok(dir)
}
```

Then in `run()`: `Allow`/`Block` arms become `apply_edit(&require_sandbox_dir(paths, name)?, ...)`; `Git(Allow)`/`Git(Block)`/`Enforce` arms become `edit_policy_file(&require_sandbox_dir(paths, name)?, ...)`. Refactor `show()` and `enable()` to call the helper instead of their inline duplicate guard (identical behavior, DRY).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p izba-cli policy`
Expected: PASS, including the pre-existing `allow_then_block_round_trips_a_policy_file`.

- [ ] **Step 5: fmt/clippy + commit**

```bash
cargo fmt && cargo clippy -p izba-cli --all-targets -- -D warnings
git add crates/izba-cli/src/commands/policy.rs
git commit -m "fix(cli): policy mutating verbs report 'no such sandbox' instead of a raw OS error

Closes #82."
```

---

### Task 2: strict, friendly egress-policy YAML parsing (#138 + #83)

**Files:**
- Modify: `crates/izba-core/src/daemon/egress/config.rs` (`from_yaml` at ~196, delete `RawConfig` at ~148, new helpers, new tests in the existing `mod tests`)
- Modify: `README.md` (egress-policy section, the paragraph around the `policy.yaml` example at ~lines 70-90)

**Interfaces:**
- Consumes: nothing new.
- Produces: `EgressPolicyConfig::from_yaml(s: &str) -> anyhow::Result<Self>` — signature UNCHANGED, semantics now strict. Every existing ingestion path (`persist_policy`, `load`, `load_or_materialize`, `edit_policy_file`, daemon `resolve_policy`) inherits the strictness with zero call-site changes.

- [ ] **Step 1: Write the failing tests** — append to `mod tests` in `config.rs`:

```rust
fn parse_err(yaml: &str) -> String {
    format!("{:#}", EgressPolicyConfig::from_yaml(yaml).expect_err("must reject"))
}

#[test]
fn rejects_unknown_top_level_key() {
    let msg = parse_err("bad_field: true\n");
    assert!(msg.contains("unknown key 'bad_field'"), "{msg}");
    assert!(msg.contains("enforce, allow, git"), "{msg}");
}

#[test]
fn rejects_unknown_allow_entry_key_instead_of_permissive_fallback() {
    // The #138 footgun: `portz` typo used to be silently dropped, widening
    // the entry to the permissive default ports.
    let msg = parse_err("allow:\n  - host: example.com\n    portz: [80]\n");
    assert!(msg.contains("allow[0]"), "{msg}");
    assert!(msg.contains("unknown key 'portz'"), "{msg}");
    assert!(msg.contains("host, ports, access"), "{msg}");
}

#[test]
fn rejects_unknown_git_entry_key_with_valid_alternatives() {
    // The #83 F3b repro: `target:` instead of `repo:`/`host:`.
    let msg = parse_err("git:\n  - target: github.com/foo/bar\n");
    assert!(msg.contains("git[0]"), "{msg}");
    assert!(msg.contains("unknown key 'target'"), "{msg}");
    assert!(msg.contains("repo"), "{msg}");
    assert!(msg.contains("host"), "{msg}");
    assert!(!msg.contains("no variant of enum"), "raw serde text leaked: {msg}");
}

#[test]
fn rejects_git_entry_with_both_repo_and_host() {
    let msg = parse_err("git:\n  - repo: github.com/foo/bar\n    host: github.com\n");
    assert!(msg.contains("git[0]") && msg.contains("exactly one of 'repo' or 'host'"), "{msg}");
}

#[test]
fn rejects_git_entry_with_neither_repo_nor_host() {
    let msg = parse_err("git:\n  - access: read\n");
    assert!(msg.contains("git[0]") && msg.contains("exactly one of 'repo' or 'host'"), "{msg}");
}

#[test]
fn rejects_wrong_type_for_enforce() {
    let msg = parse_err("enforce: \"yes\"\n");
    assert!(msg.contains("enforce") && msg.contains("expected true or false"), "{msg}");
}

#[test]
fn rejects_non_list_ports() {
    let msg = parse_err("allow:\n  - host: example.com\n    ports: 80\n");
    assert!(msg.contains("allow[0].ports") && msg.contains("expected a list"), "{msg}");
}

#[test]
fn rejects_bad_access_value() {
    let msg = parse_err("allow:\n  - host: example.com\n    access: rw\n");
    assert!(msg.contains("allow[0].access"), "{msg}");
    assert!(msg.contains("'read' or 'read-write'"), "{msg}");
}

#[test]
fn rejects_scoped_allow_entry_without_host() {
    let msg = parse_err("allow:\n  - ports: [80]\n");
    assert!(msg.contains("allow[0]") && msg.contains("'host'"), "{msg}");
}

#[test]
fn error_text_never_leaks_serde_internals() {
    for bad in [
        "git:\n  - target: x\n",
        "allow:\n  - host: h\n    portz: [80]\n",
        "bad_field: true\n",
        "allow: 5\n",
        "git: {}\n",
    ] {
        let msg = parse_err(bad);
        for leak in ["no variant of enum", "untagged enum", "flattened data", "RawConfig"] {
            assert!(!msg.contains(leak), "input {bad:?} leaked {leak:?}: {msg}");
        }
    }
}

#[test]
fn explicit_null_enforce_still_defaults_true() {
    // `enforce:` with no value parsed as enforce=true before; preserve it.
    let cfg = EgressPolicyConfig::from_yaml("enforce:\nallow:\n  - example.com\n").unwrap();
    assert!(cfg.enforce);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p izba-core egress::config`
Expected: the new tests FAIL (unknown keys currently parse fine / raw serde text present); pre-existing tests PASS.

- [ ] **Step 3: Implement the manual parser** — in `config.rs`, delete `struct RawConfig` entirely and replace `from_yaml` + add helpers (module-private, placed right after the `impl EgressPolicyConfig` block or inside it as shown):

```rust
    /// Parse the YAML policy file. An empty/comment-only file is a valid
    /// deny-all — a declared-but-allow-nothing sandbox. A present file without
    /// an explicit `enforce:` key defaults to `enforce: true` (authoring intent).
    ///
    /// Parsed MANUALLY over `serde_yaml::Value`, not via the derived
    /// `Deserialize`: the untagged `AllowEntry` and flattened `GitRule` make
    /// `#[serde(deny_unknown_fields)]` inert, and a typo'd key silently
    /// falling back to the permissive default is a security footgun (#138).
    /// The manual walk hard-rejects unknown keys at every level and names the
    /// offending field path plus its valid alternatives (#83). The derived
    /// impls remain for the `izba.yml` manifest path and for serialization.
    pub fn from_yaml(s: &str) -> Result<Self> {
        // serde_yaml maps an all-comments/empty document to `null`; treat that
        // as present-but-empty (enforce=true, no rules). Syntax errors keep
        // serde_yaml's "at line N column M" location.
        let doc: serde_yaml::Value =
            serde_yaml::from_str(s).context("parsing egress policy YAML")?;
        Self::from_value(&doc)
    }

    fn from_value(doc: &serde_yaml::Value) -> Result<Self> {
        use serde_yaml::Value;
        let map = match doc {
            Value::Null => {
                return Ok(Self {
                    enforce: true,
                    allow: vec![],
                    git: vec![],
                })
            }
            Value::Mapping(m) => m,
            other => anyhow::bail!(
                "egress policy must be a YAML mapping (valid keys: enforce, allow, git), got {}",
                yaml_kind(other)
            ),
        };
        let mut enforce = None;
        let mut allow = Vec::new();
        let mut git = Vec::new();
        for (k, v) in map {
            match key_str("egress policy", k)?.as_str() {
                // `enforce:` with no value (null) keeps the key-absent default.
                "enforce" if v.is_null() => {}
                "enforce" => enforce = Some(as_bool("enforce", v)?),
                "allow" => {
                    let Value::Sequence(items) = v else {
                        anyhow::bail!("allow: expected a list of entries, got {}", yaml_kind(v));
                    };
                    allow = items
                        .iter()
                        .enumerate()
                        .map(|(i, e)| parse_allow_entry(i, e))
                        .collect::<Result<_>>()?;
                }
                "git" => {
                    let Value::Sequence(items) = v else {
                        anyhow::bail!("git: expected a list of entries, got {}", yaml_kind(v));
                    };
                    git = items
                        .iter()
                        .enumerate()
                        .map(|(i, e)| parse_git_rule(i, e))
                        .collect::<Result<_>>()?;
                }
                other => anyhow::bail!(
                    "unknown key '{other}' in egress policy (valid keys: enforce, allow, git); \
                     see the egress-policy section in README.md"
                ),
            }
        }
        Ok(Self {
            // Present file without `enforce:` → enforce (authoring = intent).
            enforce: enforce.unwrap_or(true),
            allow,
            git,
        })
    }
```

And the free helpers (file-private, after the `impl` block):

```rust
/// Human name for a YAML value's type, for parse-error messages.
fn yaml_kind(v: &serde_yaml::Value) -> &'static str {
    use serde_yaml::Value;
    match v {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Sequence(_) => "a list",
        Value::Mapping(_) => "a mapping",
        Value::Tagged(_) => "a tagged value",
    }
}

fn key_str(ctx: &str, k: &serde_yaml::Value) -> Result<String> {
    match k {
        serde_yaml::Value::String(s) => Ok(s.clone()),
        other => anyhow::bail!("{ctx}: mapping keys must be strings, got {}", yaml_kind(other)),
    }
}

fn as_str(field: &str, v: &serde_yaml::Value) -> Result<String> {
    match v {
        serde_yaml::Value::String(s) => Ok(s.clone()),
        other => anyhow::bail!("{field}: expected a string, got {}", yaml_kind(other)),
    }
}

fn as_bool(field: &str, v: &serde_yaml::Value) -> Result<bool> {
    match v {
        serde_yaml::Value::Bool(b) => Ok(*b),
        other => anyhow::bail!("{field}: expected true or false, got {}", yaml_kind(other)),
    }
}

fn as_port(field: &str, v: &serde_yaml::Value) -> Result<u16> {
    if let serde_yaml::Value::Number(n) = v {
        if let Some(p) = n.as_u64().and_then(|p| u16::try_from(p).ok()) {
            return Ok(p);
        }
    }
    anyhow::bail!("{field}: expected a port number (0-65535), got {}", yaml_kind(v))
}

fn parse_ports(field: &str, v: &serde_yaml::Value) -> Result<Vec<u16>> {
    let serde_yaml::Value::Sequence(items) = v else {
        anyhow::bail!("{field}: expected a list of port numbers, got {}", yaml_kind(v));
    };
    items
        .iter()
        .enumerate()
        .map(|(j, p)| as_port(&format!("{field}[{j}]"), p))
        .collect()
}

fn parse_access(field: &str, v: &serde_yaml::Value) -> Result<Access> {
    if let serde_yaml::Value::String(s) = v {
        match s.as_str() {
            "read" => return Ok(Access::Read),
            "read-write" => return Ok(Access::ReadWrite),
            other => anyhow::bail!("{field}: expected 'read' or 'read-write', got '{other}'"),
        }
    }
    anyhow::bail!("{field}: expected 'read' or 'read-write', got {}", yaml_kind(v))
}

fn parse_allow_entry(i: usize, v: &serde_yaml::Value) -> Result<AllowEntry> {
    use serde_yaml::Value;
    match v {
        // Bare host string → default web ports, read-write.
        Value::String(s) => Ok(AllowEntry::Host(s.clone())),
        Value::Mapping(m) => {
            let mut host = None;
            let mut ports = None;
            let mut access = Access::default();
            for (k, val) in m {
                match key_str(&format!("allow[{i}]"), k)?.as_str() {
                    "host" => host = Some(as_str(&format!("allow[{i}].host"), val)?),
                    "ports" => ports = Some(parse_ports(&format!("allow[{i}].ports"), val)?),
                    "access" => access = parse_access(&format!("allow[{i}].access"), val)?,
                    other => anyhow::bail!(
                        "allow[{i}]: unknown key '{other}' (valid keys: host, ports, access)"
                    ),
                }
            }
            let host = host.ok_or_else(|| {
                anyhow::anyhow!("allow[{i}]: missing required key 'host'")
            })?;
            Ok(AllowEntry::Scoped { host, ports, access })
        }
        other => anyhow::bail!(
            "allow[{i}]: expected a host string or a mapping with keys host, ports, access; \
             got {}",
            yaml_kind(other)
        ),
    }
}

fn parse_git_rule(i: usize, v: &serde_yaml::Value) -> Result<GitRule> {
    use serde_yaml::Value;
    let Value::Mapping(m) = v else {
        anyhow::bail!(
            "git[{i}]: expected a mapping with keys repo (or host) and access, got {}",
            yaml_kind(v)
        );
    };
    let mut target: Option<GitTarget> = None;
    let mut access = Access::default();
    for (k, val) in m {
        let key = key_str(&format!("git[{i}]"), k)?;
        match key.as_str() {
            "repo" | "host" => {
                if target.is_some() {
                    anyhow::bail!("git[{i}]: exactly one of 'repo' or 'host' is required");
                }
                let s = as_str(&format!("git[{i}].{key}"), val)?;
                target = Some(if key == "repo" {
                    GitTarget::Repo(s)
                } else {
                    GitTarget::Host(s)
                });
            }
            "access" => access = parse_access(&format!("git[{i}].access"), val)?,
            other => anyhow::bail!(
                "git[{i}]: unknown key '{other}' (valid keys: repo, host, access)"
            ),
        }
    }
    let target = target.ok_or_else(|| {
        anyhow::anyhow!("git[{i}]: exactly one of 'repo' or 'host' is required")
    })?;
    Ok(GitRule { target, access })
}
```

Ensure `anyhow::{anyhow, bail}` usage compiles (the file already imports `anyhow::{Context, Result}`; the helpers use fully-qualified `anyhow::bail!`/`anyhow::anyhow!` so no import change is needed).

- [ ] **Step 4: Run the full izba-core test suite**

Run: `cargo test -p izba-core`
Expected: PASS — all new tests plus every pre-existing config test (`parses_bare_host_as_default_web_ports`, `parses_scoped_host_with_explicit_ports`, `parses_host_access_read`, `parses_git_block_repo_and_host`, `present_file_without_enforce_defaults_true`, `empty_document_is_enforcing_deny_all`, `new_grammar_round_trips`, wildcard-syntax tests, ...). If a pre-existing test fed a policy with keys outside the documented schema, inspect it: the schema keys are exactly `enforce`/`allow`/`git` + entry keys shown above; fix the test only if it was relying on the silent-drop bug.

- [ ] **Step 5: README note** — in the egress-policy section of `README.md` (right after the `policy.yaml` example block at ~lines 70-83), add one sentence:

```markdown
Unknown keys anywhere in `policy.yaml` are rejected with an error naming the
key and its valid alternatives — a typo can never silently widen egress scope.
```

- [ ] **Step 6: fmt/clippy + commit**

```bash
cargo fmt && cargo clippy -p izba-core --all-targets -- -D warnings
git add crates/izba-core/src/daemon/egress/config.rs README.md
git commit -m "fix(core): strict, friendly egress-policy YAML parsing

Unknown keys at any level are now hard errors naming the offending field
path and the valid keys (the untagged/flattened schema made
deny_unknown_fields inert); wrong-typed values get actionable messages
with no raw serde-internal text. Closes #138. Closes #83."
```

---

### Task 3: surface policy parse errors on `izba policy reload` (#138/#83 reload AC)

**Files:**
- Modify: `crates/izba-core/src/daemon/server.rs` (the `DaemonRequest::ReloadPolicy` arm at ~358-362; tests in the same file's `mod tests` ~1015+)

**Interfaces:**
- Consumes: `EgressPolicyConfig::load(&dir) -> Result<Option<EgressPolicyConfig>>` (Task 2 made it strict).
- Produces: no new symbols; `ReloadPolicy` now answers `DaemonResponse::Error` when `policy.yaml` is unreadable/invalid, and does NOT swap the live policy in that case.

- [ ] **Step 1: Write the failing test** — in `server.rs`'s test module, following the pattern of the existing daemon tests there (they build a test daemon with a fake image resolver and a tempdir; mirror `create_then_list_and_inspect`'s setup). Create a sandbox via the existing `create_req` helper, write a broken `policy.yaml` into its dir, then send `ReloadPolicy`:

```rust
#[test]
fn reload_policy_surfaces_parse_error_instead_of_silent_deny_all() {
    // Mirror create_then_list_and_inspect's daemon+tempdir setup.
    let (d, _tmp) = test_daemon(); // use the file's existing helper name
    handle(&d, create_req("fw")).expect("create");
    let dir = d.paths.sandbox_dir("fw");
    std::fs::write(dir.join("policy.yaml"), "portz: [80]\n").unwrap();
    let resp = handle(&d, DaemonRequest::ReloadPolicy { name: "fw".into() });
    // The daemon must refuse the reload and name the offending key, not
    // silently arm deny-all and answer Ok.
    match resp {
        Err(e) => {
            let msg = format!("{e:#}");
            assert!(msg.contains("portz"), "{msg}");
        }
        Ok(other) => panic!("expected error, got {other:?}"),
    }
}
```

(Adapt helper names — `test_daemon`/`handle`/`create_req` — to the actual ones in `server.rs`'s test module; keep the assertion shape: a broken `policy.yaml` + `ReloadPolicy` must yield an error mentioning the offending key.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p izba-core reload_policy_surfaces`
Expected: FAIL — today the handler answers `Ok` (deny-all armed silently).

- [ ] **Step 3: Implement** — change the `ReloadPolicy` arm:

```rust
        DaemonRequest::ReloadPolicy { name } => {
            sandbox_must_exist(&d.paths, &name)?;
            // Validate BEFORE swapping: a broken policy.yaml must surface to
            // the caller (#138/#83), not silently arm deny-all — the live
            // policy stays unchanged. (resolve_policy still fails closed for
            // the unattended paths: daemon start / ensure_listening.)
            crate::daemon::egress::config::EgressPolicyConfig::load(&d.paths.sandbox_dir(&name))?;
            d.egress.reload_policy(&d.paths, &name);
            Ok(DaemonResponse::Ok)
        }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p izba-core daemon::server`
Expected: PASS, including pre-existing reload/e2e-adjacent unit tests.

- [ ] **Step 5: fmt/clippy + commit**

```bash
cargo fmt && cargo clippy -p izba-core --all-targets -- -D warnings
git add crates/izba-core/src/daemon/server.rs
git commit -m "fix(daemon): ReloadPolicy rejects a broken policy.yaml instead of silently arming deny-all"
```

---

### Task 4: validate `--policy` before the Create RPC (#139)

**Files:**
- Modify: `crates/izba-cli/src/commands/mod.rs` (`persist_policy` at ~237-254 → split; tests in the same file)
- Modify: `crates/izba-cli/src/commands/create.rs` (`run` at ~9-44)
- Modify: `crates/izba-cli/src/commands/run.rs` (`resolve_or_create` at ~217-274; `reconcile_existing` stays on `persist_policy`)

**Interfaces:**
- Consumes: `EgressPolicyConfig::from_yaml` (strict, Task 2).
- Produces (in `commands/mod.rs`, both `pub(crate)`):
  - `fn read_policy(policy: Option<&Path>) -> anyhow::Result<Option<String>>` — read + validate, NO side effects.
  - `fn write_policy(paths: &izba_core::paths::Paths, name: &str, raw: Option<&str>) -> anyhow::Result<()>` — persist pre-validated text into the sandbox dir.
  - `persist_policy` becomes `read_policy` + `write_policy` composed (same signature/behavior; still used by `reconcile_existing`).

- [ ] **Step 1: Write the failing tests** — in `commands/mod.rs`'s `mod tests`:

```rust
#[test]
fn read_policy_missing_file_errors() {
    let err = read_policy(Some(std::path::Path::new("/nonexistent-policy.yaml")))
        .expect_err("missing file must fail");
    assert!(format!("{err:#}").contains("reading egress policy"), "{err:#}");
}

#[test]
fn read_policy_invalid_content_errors() {
    let tmp = tempfile::tempdir().unwrap();
    let f = tmp.path().join("p.yaml");
    std::fs::write(&f, "allow:\n  - host: example.com\n    portz: [80]\n").unwrap();
    let err = read_policy(Some(&f)).expect_err("bad key must fail");
    let msg = format!("{err:#}");
    assert!(msg.contains("invalid egress policy"), "{msg}");
    assert!(msg.contains("portz"), "{msg}");
}

#[test]
fn read_policy_none_is_none() {
    assert!(read_policy(None).unwrap().is_none());
}

#[test]
fn write_policy_persists_validated_text() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = Paths::with_root(tmp.path().to_path_buf());
    std::fs::create_dir_all(paths.sandbox_dir("fw")).unwrap();
    let raw = "enforce: true\nallow:\n  - example.com\n";
    write_policy(&paths, "fw", Some(raw)).unwrap();
    let dst = EgressPolicyConfig::path_in(&paths.sandbox_dir("fw"));
    assert_eq!(std::fs::read_to_string(dst).unwrap(), raw);
    // None is a no-op.
    write_policy(&paths, "fw", None).unwrap();
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p izba-cli read_policy`
Expected: FAIL to COMPILE (`read_policy`/`write_policy` don't exist yet).

- [ ] **Step 3: Implement the split** — in `commands/mod.rs`, replace `persist_policy` with:

```rust
/// Read and validate a `--policy` file WITHOUT touching any sandbox state,
/// returning the raw YAML to persist after the sandbox exists. Runs BEFORE
/// the daemon Create RPC so a missing/invalid file fails the invocation
/// without leaving a stub sandbox registered (#139).
pub(crate) fn read_policy(policy: Option<&Path>) -> anyhow::Result<Option<String>> {
    use izba_core::daemon::egress::config::EgressPolicyConfig;
    let Some(src) = policy else {
        return Ok(None);
    };
    let raw = std::fs::read_to_string(src)
        .with_context(|| format!("reading egress policy {}", src.display()))?;
    // Fail fast at create on a malformed allow-list rather than at boot.
    EgressPolicyConfig::from_yaml(&raw)
        .with_context(|| format!("invalid egress policy {}", src.display()))?;
    Ok(Some(raw))
}

/// Persist pre-validated policy text into the sandbox directory as
/// `policy.yaml` (the daemon loads it when arming the sandbox's egress
/// plane). No-op for `None`. Must run after the sandbox dir exists.
pub(crate) fn write_policy(
    paths: &izba_core::paths::Paths,
    name: &str,
    raw: Option<&str>,
) -> anyhow::Result<()> {
    use izba_core::daemon::egress::config::EgressPolicyConfig;
    let Some(raw) = raw else {
        return Ok(());
    };
    let dst = EgressPolicyConfig::path_in(&paths.sandbox_dir(name));
    std::fs::write(&dst, raw).with_context(|| format!("writing {}", dst.display()))?;
    Ok(())
}

/// Validate a `--policy` file and persist it into the sandbox directory —
/// [`read_policy`] + [`write_policy`] composed, for call sites where the
/// sandbox already exists (run's reconcile path).
pub(crate) fn persist_policy(
    paths: &izba_core::paths::Paths,
    name: &str,
    policy: Option<&Path>,
) -> anyhow::Result<()> {
    let raw = read_policy(policy)?;
    write_policy(paths, name, raw.as_deref())
}
```

In `create.rs` `run()`: after `let volumes = ...` and BEFORE `DaemonClient::connect`, insert:

```rust
    // Validate --policy BEFORE the daemon Create RPC: a missing or invalid
    // file must fail here, leaving no stub sandbox registered (#139).
    let policy_raw = super::read_policy(merged.policy.as_deref())?;
```

and in the `Created` arm replace `super::persist_policy(paths, &name, merged.policy.as_deref())?;` with `super::write_policy(paths, &name, policy_raw.as_deref())?;`.

In `run.rs` `resolve_or_create()`: after `let volumes = super::parse_volumes(&merged.volumes)?;` insert the same `read_policy` call (same comment), and replace the post-`Created` `super::persist_policy(paths, &name, merged.policy.as_deref())?;` with `super::write_policy(paths, &name, policy_raw.as_deref())?;`. `reconcile_existing` keeps calling `persist_policy` (the sandbox already exists there — its two `reconcile_*` tests must stay green).

- [ ] **Step 4: Run the izba-cli suite**

Run: `cargo test -p izba-cli`
Expected: PASS (including `reconcile_repersists_edited_policy_on_existing_sandbox` and `reconcile_without_policy_leaves_stored_policy_intact`).

- [ ] **Step 5: fmt/clippy + commit**

```bash
cargo fmt && cargo clippy -p izba-cli --all-targets -- -D warnings
git add crates/izba-cli/src/commands/mod.rs crates/izba-cli/src/commands/create.rs crates/izba-cli/src/commands/run.rs
git commit -m "fix(cli): validate --policy before the Create RPC so failures leave no stub sandbox

Closes #139."
```

---

### Task 5: binary-level failure-path tests for `create --policy` (#139 + #138 CLI AC)

**Files:**
- Create: `crates/izba-cli/tests/create_policy_failures.rs`

**Interfaces:**
- Consumes: the Task 4 ordering (validation precedes any daemon contact, so these tests need NO daemon, NO network, NO KVM — they run in the default `cargo test --workspace` gate).

- [ ] **Step 1: Write the tests**

```rust
//! `izba create --policy` failure paths: a missing or invalid policy file
//! must fail the invocation BEFORE any sandbox state exists (#139) and
//! unknown policy keys must be rejected loudly (#138). Validation happens
//! before the daemon is contacted, so these run without a daemon/VM.

use std::path::Path;
use std::process::{Command, Output};

fn izba(data: &Path, cwd: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_izba"))
        .args(args)
        .current_dir(cwd)
        .env("IZBA_DATA_DIR", data)
        // Defensive: if a daemon ever does get spawned, let it self-exit fast.
        .env("IZBA_DAEMON_IDLE_SECS", "2")
        .output()
        .expect("run izba")
}

fn no_sandbox_registered(data: &Path, name: &str) {
    let dir = data.join("sandboxes").join(name);
    assert!(!dir.exists(), "stub sandbox left behind at {}", dir.display());
}

#[test]
fn create_with_missing_policy_file_leaves_no_stub() {
    let data = tempfile::tempdir().unwrap();
    let ws = tempfile::tempdir().unwrap();
    let out = izba(
        data.path(),
        ws.path(),
        &["create", "--name", "stubtest", "--policy", "/nonexistent-policy.yaml"],
    );
    assert!(!out.status.success(), "create must fail");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("reading egress policy"), "stderr: {err}");
    no_sandbox_registered(data.path(), "stubtest");
}

#[test]
fn create_with_unknown_policy_key_fails_loud_and_leaves_no_stub() {
    let data = tempfile::tempdir().unwrap();
    let ws = tempfile::tempdir().unwrap();
    let policy = ws.path().join("policy.yaml");
    std::fs::write(&policy, "allow:\n  - host: example.com\n    portz: [80]\n").unwrap();
    let out = izba(
        data.path(),
        ws.path(),
        &["create", "--name", "stubtest", "--policy", policy.to_str().unwrap()],
    );
    assert!(!out.status.success(), "create must fail");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("portz"), "must name the offending key; stderr: {err}");
    assert!(err.contains("valid keys"), "must list valid keys; stderr: {err}");
    no_sandbox_registered(data.path(), "stubtest");
}

#[test]
fn failing_create_leaves_preexisting_sandbox_untouched() {
    let data = tempfile::tempdir().unwrap();
    let ws = tempfile::tempdir().unwrap();
    // Seed a fake pre-existing sandbox of the same name.
    let dir = data.path().join("sandboxes").join("stubtest");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("config.json"), "{}").unwrap();
    std::fs::write(dir.join("marker"), "precious").unwrap();
    let out = izba(
        data.path(),
        ws.path(),
        &["create", "--name", "stubtest", "--policy", "/nonexistent-policy.yaml"],
    );
    assert!(!out.status.success(), "create must fail");
    // The pre-existing sandbox must be completely untouched by the failure.
    assert_eq!(std::fs::read_to_string(dir.join("marker")).unwrap(), "precious");
    assert!(dir.join("config.json").exists());
}
```

- [ ] **Step 2: Run the tests**

Run: `cargo test -p izba-cli --test create_policy_failures`
Expected: PASS on the Task-4 code. If the first two ever hang or try to reach a daemon, the Task-4 ordering regressed — validation must precede `DaemonClient::connect`.

- [ ] **Step 3: fmt/clippy + commit**

```bash
cargo fmt && cargo clippy -p izba-cli --all-targets -- -D warnings
git add crates/izba-cli/tests/create_policy_failures.rs
git commit -m "test(cli): create --policy failure paths leave no stub sandbox and reject unknown keys"
```

---

### Task 6: full gates, push, PR, CI/greploop/Sonar

**Files:** none new (fixups only if a gate fails).

- [ ] **Step 1: Run ALL six workspace gates** (see Global Constraints). All must pass. Note: this change alters NO public type signatures in izba-core (only `from_yaml` behavior + a private struct deletion + one daemon handler arm), so the separate `app/src-tauri` gate is not triggered per CLAUDE.md's rule; the cross-compile gates still run.
- [ ] **Step 2: Push the branch** (`git push -u origin worktree-bugfix-policy-ux`) and open a PR titled `fix: policy validation & error UX (closes #82, #83, #138, #139)` with a body summarizing the four fixes, the locked hard-error decision for #138, and the Claude Code attribution trailer.
- [ ] **Step 3: Watch CI** (`gh pr checks --watch`); fix and re-push until all required checks are green.
- [ ] **Step 4: Run the greploop skill** on the PR until Greptile reports 5/5 with zero unresolved comments.
- [ ] **Step 5: Check SonarCloud quality gate** on the PR (sonarqube MCP `get_project_quality_gate_status` with the PR key); resolve any new findings.
