# Host custom CA bundles (#283) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Corporate / private-PKI users can drop PEM files into a host-only
directory and every sandbox trusts those CAs — from inside the guest (bare
sandbox, raw TCP splice) AND at izbad's upstream leg (enforcing sandbox, TLS
terminated + re-originated).

**Architecture:** One host-only source of truth, `<data>/trust/extra/*.pem|*.crt`
(sorted by file name; never shared into a VM as a directory). Two consumers of
the same loader (`izba_core::trust::load_extra_cas`): (1) `sandbox::start`
writes the concatenated PEM text as `trust/extra.pem` next to the per-sandbox
`trust/ca.pem` copy, delivered over the existing read-only `izba-trust` virtiofs
share, and `izba-init` folds it into the guest anchors (`/etc/izba/ca.pem` =
izba CA + extras) and bundle (`/etc/izba/ca-bundle.pem` = anchors + system
roots); (2) `build_mitm_runtime` builds the upstream `ClientConfig` root store
as webpki-roots + every extra cert. Reload semantics: guest side on the next
`izba start`; izbad side at daemon start (`izba daemon stop`, the next command
respawns it). No new wire request → NO `DAEMON_PROTO_VERSION` bump; the one
additive `DaemonStatus` field is `#[serde(default)]`.

**Tech Stack:** Rust; rustls 0.23 / rustls-pki-types (`CertificateDer::pem_slice_iter`),
webpki-roots, rcgen (via `IzbaCa`) + tokio-rustls for the test upstream,
hickory-proto 0.26 for the test resolver.

**Spec:** GitHub issue Lupus/izba#283 (body reproduced in the task rationale
below). Open design question settled here: **explicit directory only**; OS
trust-store auto-import (rustls-native-certs) is DEFERRED — Task 7 files the
follow-up issue.

## Global Constraints

- All six workspace gates green before every commit (see CLAUDE.md "Build &
  test"): `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo fmt --check`, the musl `izba-init` build, and the two
  `x86_64-pc-windows-gnu` cross gates. Run `[ -f .cargo-env ] && source .cargo-env` first.
- Task 5 touches `DaemonStatus` (a public `izba-core` type) → ALSO run the app
  gate: `cd app && npm ci && npm run build && npm run test && (cd src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test)`.
- Unit tests never bind listeners (use in-memory `tokio::io::duplex` like
  `ca.rs`'s `reloaded_ca_signs_leaves_trusted_by_the_persisted_cert`).
- Conventional commits (`feat(core): …`, `test(core): …`, `docs: …`). TDD: the
  failing test is written and run BEFORE the implementation in every task.
- Loud on degradation: an unparsable extra-CA file is a hard error (start
  refuses; the daemon logs and disables the MITM so enforcing sandboxes fail
  closed) — never a silent skip.
- Nothing under `<data>/trust/` is ever shared as a directory into a guest; the
  guest only ever sees the per-sandbox `trust/` copy on a read-only share.
- KVM e2e runs unsandboxed: `IZBA_INTEGRATION=1 cargo test -p izba-core --test integration -- --test-threads=1 custom_ca`
  (docs/testing.md). The KVM device is invisible inside the sandboxed Bash only.

---

### Task 1: Host-side extra-CA loader

**Files:**
- Create: `crates/izba-core/src/trust.rs`
- Modify: `crates/izba-core/src/lib.rs` (add `pub mod trust;` between `state` and `usb`, alphabetical)
- Modify: `crates/izba-core/src/paths.rs:100-104` (add `trust_extra_dir()` after `ca_dir()`)

**Interfaces:**
- Produces: `Paths::trust_extra_dir(&self) -> PathBuf` = `<root>/trust/extra`.
- Produces: `pub struct ExtraCaFile { pub name: String, pub pem: String, pub certs: Vec<CertificateDer<'static>> }`.
- Produces: `pub fn load_extra_cas(dir: &Path) -> anyhow::Result<Vec<ExtraCaFile>>`
  (missing dir ⇒ `Ok(vec![])`; only `*.pem`/`*.crt` (case-insensitive ext),
  non-dotfiles, sorted by file name; a file with a bad block or zero
  CERTIFICATE blocks ⇒ `Err` naming the file).
- Produces: `pub fn guest_extra_pem(files: &[ExtraCaFile]) -> String` (each
  file's text trimmed, joined by `\n`, trailing `\n`; empty string for none).

- [ ] **Step 1: Write the failing tests**

Create `crates/izba-core/src/trust.rs` with ONLY the module doc + test module:

```rust
//! Host-installed extra CA roots (#283): `<data>/trust/extra/*.pem|*.crt`.
//!
//! One loader, two consumers, so the guest and izbad can never disagree about
//! which roots are trusted:
//! - `sandbox::start` ships the files' text to the guest as `trust/extra.pem`
//!   on the read-only `izba-trust` share (guest side: next sandbox start);
//! - `daemon::server::build_mitm_runtime` adds the parsed certs to izbad's
//!   upstream verifier on top of webpki-roots (izbad side: daemon start).
//!
//! The directory is host-only authority, like `policy.yaml` (F-30): it is
//! never shared into a VM — only a per-sandbox COPY of its text is.

use std::path::Path;

use anyhow::{bail, Context, Result};
use rustls::pki_types::{pem::PemObject, CertificateDer};

#[cfg(test)]
mod tests {
    use super::*;

    const CA_A: &str = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";

    /// A real, parseable CA PEM (rcgen via IzbaCa); tests that only need
    /// ordering use the fake `CA_A` text and never parse it.
    fn real_ca_pem() -> String {
        let _ = rustls::crypto::ring::default_provider().install_default();
        crate::daemon::egress::mitm::IzbaCa::generate()
            .unwrap()
            .cert_pem()
            .to_string()
    }

    #[test]
    fn missing_dir_loads_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let files = load_extra_cas(&dir.path().join("absent")).unwrap();
        assert!(files.is_empty());
    }

    #[test]
    fn loads_pem_and_crt_sorted_by_name_ignoring_others() {
        let dir = tempfile::tempdir().unwrap();
        let ca = real_ca_pem();
        std::fs::write(dir.path().join("zeta.pem"), &ca).unwrap();
        std::fs::write(dir.path().join("alpha.CRT"), &ca).unwrap();
        std::fs::write(dir.path().join("README.md"), "not a cert").unwrap();
        std::fs::write(dir.path().join(".hidden.pem"), &ca).unwrap();
        std::fs::create_dir(dir.path().join("sub.pem")).unwrap();
        let files = load_extra_cas(dir.path()).unwrap();
        let names: Vec<&str> = files.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["alpha.CRT", "zeta.pem"]);
        assert_eq!(files[0].certs.len(), 1);
        assert_eq!(files[0].pem, ca);
    }

    #[test]
    fn counts_every_cert_in_a_multi_cert_file() {
        let dir = tempfile::tempdir().unwrap();
        let ca = real_ca_pem();
        std::fs::write(dir.path().join("chain.pem"), format!("{ca}{ca}")).unwrap();
        let files = load_extra_cas(dir.path()).unwrap();
        assert_eq!(files[0].certs.len(), 2);
    }

    #[test]
    fn a_file_with_no_certificates_is_an_error_naming_the_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("empty.pem"), "just text\n").unwrap();
        let err = load_extra_cas(dir.path()).unwrap_err().to_string();
        assert!(err.contains("empty.pem"), "{err}");
        assert!(err.contains("no CERTIFICATE"), "{err}");
    }

    #[test]
    fn a_corrupt_block_is_an_error_naming_the_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("bad.pem"), CA_A).unwrap();
        let err = load_extra_cas(dir.path()).unwrap_err().to_string();
        assert!(err.contains("bad.pem"), "{err}");
    }

    #[test]
    fn guest_extra_pem_joins_files_in_order_with_single_newlines() {
        let files = vec![
            ExtraCaFile {
                name: "a.pem".into(),
                pem: "A-PEM".into(), // unterminated
                certs: vec![],
            },
            ExtraCaFile {
                name: "b.pem".into(),
                pem: "B-PEM\n\n".into(), // over-terminated
                certs: vec![],
            },
        ];
        assert_eq!(guest_extra_pem(&files), "A-PEM\nB-PEM\n");
        assert_eq!(guest_extra_pem(&[]), "");
    }
}
```

Add `pub mod trust;` to `crates/izba-core/src/lib.rs` (after `pub mod state;`).

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p izba-core trust::tests`
Expected: compile error — `load_extra_cas`, `ExtraCaFile`, `guest_extra_pem` not found.

- [ ] **Step 3: Implement the loader**

Insert between the `use` lines and `#[cfg(test)]`:

```rust
/// File extensions the loader picks up (case-insensitive). Anything else in
/// the directory (README, `.bak`, dotfiles, subdirectories) is ignored.
pub const EXTRA_CA_EXTENSIONS: [&str; 2] = ["pem", "crt"];

/// One file from the extra-CA directory.
#[derive(Debug, Clone)]
pub struct ExtraCaFile {
    /// File name inside the directory — the ordering key and what
    /// `izba daemon status` prints.
    pub name: String,
    /// The file's text verbatim: what the guest receives. Text outside the
    /// PEM blocks (comments) is harmless to every consumer (OpenSSL, curl,
    /// Node, Python) and keeps the operator's annotations.
    pub pem: String,
    /// Every certificate parsed from `pem`, in file order: what izbad trusts.
    pub certs: Vec<CertificateDer<'static>>,
}

/// Load every `*.pem` / `*.crt` under `dir`, sorted by file name. A missing
/// directory is simply "no extra CAs". A file that parses to zero
/// certificates, or contains a corrupt block, is a HARD error naming the file:
/// a silently skipped corporate CA would reproduce exactly the "my CA doesn't
/// work" confusion this feature exists to remove.
pub fn load_extra_cas(dir: &Path) -> Result<Vec<ExtraCaFile>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(e).with_context(|| format!("reading extra CA dir {}", dir.display()))
        }
    };
    let mut names: Vec<String> = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("listing extra CA dir {}", dir.display()))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.starts_with('.') {
            continue;
        }
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase());
        if ext
            .as_deref()
            .is_some_and(|e| EXTRA_CA_EXTENSIONS.contains(&e))
        {
            names.push(name.to_string());
        }
    }
    names.sort();

    let mut out = Vec::with_capacity(names.len());
    for name in names {
        let path = dir.join(&name);
        let pem = std::fs::read_to_string(&path)
            .with_context(|| format!("reading extra CA file {}", path.display()))?;
        let mut certs = Vec::new();
        for cert in CertificateDer::pem_slice_iter(pem.as_bytes()) {
            let cert = cert.map_err(|e| {
                anyhow::anyhow!("extra CA file {}: invalid PEM: {e}", path.display())
            })?;
            certs.push(cert);
        }
        if certs.is_empty() {
            bail!(
                "extra CA file {}: no CERTIFICATE blocks found (expected PEM)",
                path.display()
            );
        }
        out.push(ExtraCaFile { name, pem, certs });
    }
    Ok(out)
}

/// The text shipped to the guest as `trust/extra.pem`: every file's text in
/// load order, each trimmed and newline-terminated, so two files never glue
/// onto one line and the guest bundle stays well-formed. Empty when there are
/// no files (the caller then removes a stale `extra.pem` instead).
pub fn guest_extra_pem(files: &[ExtraCaFile]) -> String {
    let mut out = String::new();
    for f in files {
        out.push_str(f.pem.trim());
        out.push('\n');
    }
    out
}
```

Add to `crates/izba-core/src/paths.rs` right after `ca_dir()`:

```rust
    /// Host-only extra CA roots (`<root>/trust/extra/*.pem|*.crt`, #283):
    /// corporate / private-PKI roots every guest trusts and izbad's upstream
    /// verifier accepts. Never shared into a VM as a directory — `start`
    /// copies its text into the per-sandbox `trust/` share.
    pub fn trust_extra_dir(&self) -> PathBuf {
        self.root.join("trust").join("extra")
    }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p izba-core trust::tests`
Expected: 6 passed. (If `a_corrupt_block_is_an_error_naming_the_file` fails
because `pem_slice_iter` yields no item for the bogus base64 rather than an
error, that is fine — the "no CERTIFICATE blocks" branch then fires and the
assertion on `bad.pem` still holds; do NOT weaken the test.)

- [ ] **Step 5: Gates + commit**

Run: `cargo clippy -p izba-core --all-targets -- -D warnings && cargo fmt --check`

```bash
git add crates/izba-core/src/trust.rs crates/izba-core/src/lib.rs crates/izba-core/src/paths.rs
git commit -m "feat(core): load host-installed extra CA roots from <data>/trust/extra (#283)"
```

---

### Task 2: izbad's upstream verifier trusts webpki-roots + the extra roots

**Files:**
- Modify: `crates/izba-core/src/trust.rs` (add `upstream_client_config`)
- Modify: `crates/izba-core/src/daemon/server.rs:44-74` (`build_mitm_runtime`)
- Modify: `crates/izba-core/tests/integration.rs:1838-1870` (`setup_mitm_sandbox` uses the production builder)

**Interfaces:**
- Consumes: `load_extra_cas`, `ExtraCaFile` (Task 1); `mitm::upstream_client_config(RootCertStore) -> Arc<ClientConfig>` (existing).
- Produces: `pub fn upstream_client_config(extra: &[ExtraCaFile]) -> Arc<rustls::ClientConfig>`
  — root store = `webpki_roots::TLS_SERVER_ROOTS` + every `certs` entry of every file, ALPN http/1.1 (unchanged).
- Produces: `pub fn upstream_root_store(extra: &[ExtraCaFile]) -> rustls::RootCertStore` (what the config is built from; unit-tested directly).

- [ ] **Step 1: Write the failing tests** (append inside `mod tests` in `trust.rs`)

```rust
    #[test]
    fn upstream_roots_are_webpki_plus_every_extra_cert() {
        let ca = real_ca_pem();
        let files = vec![ExtraCaFile {
            name: "corp.pem".into(),
            pem: format!("{ca}{ca}"),
            certs: CertificateDer::pem_slice_iter(format!("{ca}{ca}").as_bytes())
                .map(|c| c.unwrap())
                .collect(),
        }];
        let roots = upstream_root_store(&files);
        assert_eq!(
            roots.len(),
            webpki_roots::TLS_SERVER_ROOTS.len() + 2,
            "webpki baseline plus both extra certs"
        );
        assert_eq!(
            upstream_root_store(&[]).len(),
            webpki_roots::TLS_SERVER_ROOTS.len(),
            "no extras ⇒ exactly the webpki baseline"
        );
    }

    /// The property izbad relies on: a leaf minted by an EXTRA CA verifies
    /// under the upstream config, and does NOT verify without that CA.
    #[test]
    fn upstream_config_verifies_a_leaf_signed_by_an_extra_ca_and_only_then() {
        use crate::daemon::egress::mitm::{server_config_with_resolver, CertCache, IzbaCa};
        use rustls::pki_types::ServerName;
        use std::sync::Arc;
        use tokio_rustls::{TlsAcceptor, TlsConnector};

        let _ = rustls::crypto::ring::default_provider().install_default();
        let corp = IzbaCa::generate().unwrap();
        let corp_pem = corp.cert_pem().to_string();
        let acceptor =
            TlsAcceptor::from(Arc::new(server_config_with_resolver(Arc::new(CertCache::new(corp)))));

        let files = vec![ExtraCaFile {
            name: "corp.pem".into(),
            pem: corp_pem.clone(),
            certs: CertificateDer::pem_slice_iter(corp_pem.as_bytes())
                .map(|c| c.unwrap())
                .collect(),
        }];

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let handshake = |cfg: Arc<rustls::ClientConfig>| {
            let acceptor = acceptor.clone();
            rt.block_on(async move {
                let (client, server) = tokio::io::duplex(16 * 1024);
                let srv = tokio::spawn(async move { acceptor.accept(server).await.map(|_| ()) });
                let name = ServerName::try_from("registry.corp.example").unwrap();
                let res = TlsConnector::from(cfg).connect(name, client).await.map(|_| ());
                let _ = srv.await;
                res
            })
        };
        handshake(upstream_client_config(&files)).expect("extra CA leaf verifies");
        handshake(upstream_client_config(&[])).expect_err("without the extra CA the leaf is refused");
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p izba-core trust::tests::upstream`
Expected: compile error — `upstream_root_store` / `upstream_client_config` not found.

- [ ] **Step 3: Implement** (add to `trust.rs` above the tests)

```rust
/// webpki-roots (the Mozilla bundle production izbad always trusted) PLUS
/// every extra cert, in load order. Only ever widens over the baseline.
pub fn upstream_root_store(extra: &[ExtraCaFile]) -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for file in extra {
        for cert in &file.certs {
            // `add` rejects a non-CA / undecodable cert; the loader already
            // proved decodability, and a leaf in the extra dir is an operator
            // mistake that must not disable the whole store — skip it loudly.
            if let Err(e) = roots.add(cert.clone()) {
                eprintln!("izbad: extra CA file {}: skipping a non-CA certificate: {e}", file.name);
            }
        }
    }
    roots
}

/// izbad's upstream `ClientConfig` (ALPN http/1.1) trusting
/// [`upstream_root_store`]. Built once at daemon start — a changed directory
/// is picked up by restarting the daemon (`izba daemon stop`).
pub fn upstream_client_config(extra: &[ExtraCaFile]) -> std::sync::Arc<rustls::ClientConfig> {
    crate::daemon::egress::mitm::upstream_client_config(upstream_root_store(extra))
}
```

Then in `crates/izba-core/src/daemon/server.rs`, replace the body of
`build_mitm_runtime` after the CA load so it reads:

```rust
    let ca = match crate::ca::load_or_create(&paths.ca_dir()) {
        Ok(ca) => ca,
        Err(e) => {
            eprintln!("izbad: egress MITM disabled — CA init failed: {e:#}");
            return None;
        }
    };
    // Extra roots (#283): a corrupt file disables the MITM (enforcing
    // sandboxes then fail closed at the router) rather than silently trusting
    // fewer roots than the operator installed. `sandbox::start` refuses with
    // the same error, so the user sees it on the very next command.
    let extra = match crate::trust::load_extra_cas(&paths.trust_extra_dir()) {
        Ok(extra) => extra,
        Err(e) => {
            eprintln!("izbad: egress MITM disabled — extra CA load failed: {e:#}");
            return None;
        }
    };
    if !extra.is_empty() {
        let names: Vec<&str> = extra.iter().map(|f| f.name.as_str()).collect();
        eprintln!(
            "izbad: trusting {} extra CA file(s) from {}: {}",
            extra.len(),
            paths.trust_extra_dir().display(),
            names.join(", ")
        );
    }
    let certs = Arc::new(CertCache::new(ca));
    match MitmRuntime::start(certs, crate::trust::upstream_client_config(&extra), audit) {
```

and drop `upstream_client_config_webpki` from the `use` line (`use crate::daemon::egress::mitm::CertCache;`).
Keep `mitm::upstream_client_config_webpki` itself — it still has callers in `egress_mitm.rs`/`egress_inspect.rs` tests.

In `crates/izba-core/tests/integration.rs` `setup_mitm_sandbox`, replace
`upstream_client_config_webpki()` with the production builder so the KVM MITM
tests exercise exactly what izbad runs:

```rust
    let extra = izba_core::trust::load_extra_cas(&tb.paths.trust_extra_dir())
        .expect("loading <data>/trust/extra");
    let mitm = std::sync::Arc::new(
        MitmRuntime::start(
            certs,
            izba_core::trust::upstream_client_config(&extra),
            audit.clone(),
        )
        .expect("start MITM runtime"),
    );
```

(and remove `upstream_client_config_webpki` from that function's `use`).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p izba-core trust::tests && cargo test -p izba-core --test integration --no-run`
Expected: 8 passed; the integration test binary compiles.

- [ ] **Step 5: Gates + commit**

Run: `cargo clippy -p izba-core --all-targets -- -D warnings && cargo fmt --check`

```bash
git add crates/izba-core/src/trust.rs crates/izba-core/src/daemon/server.rs crates/izba-core/tests/integration.rs
git commit -m "feat(core): izbad upstream verifier trusts <data>/trust/extra roots on top of webpki (#283)"
```

---

### Task 3: `sandbox::start` ships the extra roots on the `izba-trust` share

**Files:**
- Modify: `crates/izba-core/src/sandbox.rs:1005-1015` (the trust-dir block in `start`)
- Test: `crates/izba-core/src/sandbox.rs` `mod tests` (next to `start_builds_correct_spec`, ~line 2550)

**Interfaces:**
- Consumes: `crate::trust::{load_extra_cas, guest_extra_pem}`, `Paths::trust_extra_dir` (Task 1).
- Produces: the per-sandbox share file `<sandbox>/trust/extra.pem` — present iff
  the extra dir has ≥1 file; REMOVED on a start with none (so deleting a CA
  takes effect on the next start). The guest file name `extra.pem` is the
  contract Task 4 reads (`izba_init::trust::EXTRA_FILE`).

- [ ] **Step 1: Write the failing tests** (in `sandbox.rs` `mod tests`, after `start_builds_correct_spec`)

```rust
    /// #283: the extra roots ride the SAME read-only izba-trust share as the
    /// izba CA, as one concatenated `extra.pem`, in file-name order.
    #[test]
    fn start_ships_extra_cas_on_the_trust_share() {
        let (dir, paths) = test_paths();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        create(&paths, "web", &opts(&ws)).unwrap();
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca_a = crate::daemon::egress::mitm::IzbaCa::generate().unwrap();
        let ca_b = crate::daemon::egress::mitm::IzbaCa::generate().unwrap();
        fs::create_dir_all(paths.trust_extra_dir()).unwrap();
        fs::write(paths.trust_extra_dir().join("b-second.pem"), ca_b.cert_pem()).unwrap();
        fs::write(paths.trust_extra_dir().join("a-first.crt"), ca_a.cert_pem()).unwrap();

        start(&paths, "web", &MockDriver::new(), &arts(), false).unwrap();

        let shipped = fs::read_to_string(paths.sandbox_dir("web").join("trust").join("extra.pem"))
            .expect("extra.pem shipped");
        let a = shipped.find(ca_a.cert_pem().trim()).expect("a-first present");
        let b = shipped.find(ca_b.cert_pem().trim()).expect("b-second present");
        assert!(a < b, "file-name order: a-first before b-second");
        // The izba CA itself is still the separate ca.pem, untouched.
        assert!(paths.sandbox_dir("web").join("trust").join("ca.pem").exists());
    }

    /// Removing every extra CA must take effect on the next start: a stale
    /// extra.pem from an earlier boot is deleted, not left to be trusted.
    #[test]
    fn start_removes_a_stale_extra_pem_when_the_dir_is_empty() {
        let (dir, paths) = test_paths();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        create(&paths, "web", &opts(&ws)).unwrap();
        let trust = paths.sandbox_dir("web").join("trust");
        fs::create_dir_all(&trust).unwrap();
        fs::write(trust.join("extra.pem"), "STALE\n").unwrap();

        start(&paths, "web", &MockDriver::new(), &arts(), false).unwrap();

        assert!(!trust.join("extra.pem").exists(), "stale extra.pem removed");
    }

    /// A corrupt extra-CA file refuses the start with an error naming the
    /// file — never a boot that silently trusts fewer roots than installed.
    #[test]
    fn start_refuses_when_an_extra_ca_file_is_corrupt() {
        let (dir, paths) = test_paths();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        create(&paths, "web", &opts(&ws)).unwrap();
        fs::create_dir_all(paths.trust_extra_dir()).unwrap();
        fs::write(paths.trust_extra_dir().join("corp.pem"), "not a certificate\n").unwrap();

        let err = start(&paths, "web", &MockDriver::new(), &arts(), false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("corp.pem"), "{err}");
    }
```

Check the existing helpers first: `test_paths()`, `opts()`, `arts()`,
`MockDriver::new()` are defined in the same `mod tests` (~lines 2420-2460);
`start` is called there as `start(&paths, "web", &driver, &arts(), false)`.
If `start_refuses_…` needs the error chain, use `format!("{err:#}")` instead
of `.to_string()` (anyhow's `{:#}` prints the context chain).

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p izba-core sandbox::tests::start_ships_extra -- --nocapture; cargo test -p izba-core sandbox::tests::start_removes_a_stale; cargo test -p izba-core sandbox::tests::start_refuses_when`
Expected: the first fails at `expect("extra.pem shipped")`, the second at the
`!exists` assertion, the third at `unwrap_err` (start succeeds today).

- [ ] **Step 3: Implement** — in `sandbox.rs` `start`, right after the
`std::fs::write(trust_dir.join("ca.pem"), …)?;` line add:

```rust
    // #283: host-installed extra roots ride the same share as ONE file.
    // Absent ⇒ the guest sees no extra.pem (a stale one from an earlier boot
    // is removed so un-installing a CA takes effect on the next start).
    // A corrupt file refuses the start — the same loud posture as izbad's
    // MITM init — with the offending file name in the error.
    let extra = crate::trust::load_extra_cas(&paths.trust_extra_dir())
        .context("loading host extra CA roots (<data>/trust/extra)")?;
    let extra_path = trust_dir.join("extra.pem");
    if extra.is_empty() {
        match std::fs::remove_file(&extra_path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("removing stale {}", extra_path.display()))
            }
        }
    } else {
        std::fs::write(&extra_path, crate::trust::guest_extra_pem(&extra))
            .with_context(|| format!("writing extra CA roots into {}", extra_path.display()))?;
    }
```

Also update the comment block above (lines ~1005-1008) to say "Bake the izba
root CA — and any host-installed extra roots (#283) — into the guest trust
store". Then update the doc-comment on the existing `ca_present` gate at
`sandbox.rs:757-761` — replace "Today the host always writes ca.pem so this is
always-open" with "The host writes ca.pem for EVERY sandbox (bare or
enforcing) — the guest trust store is unconditional since M2, and since #283 it
also carries the extra roots — so this is always-open".

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p izba-core sandbox::tests`
Expected: all pass, including the three new ones and the untouched
`start_builds_correct_spec` (share count is still 4 — no new share).

- [ ] **Step 5: Gates + commit**

Run: `cargo clippy -p izba-core --all-targets -- -D warnings && cargo fmt --check`

```bash
git add crates/izba-core/src/sandbox.rs
git commit -m "feat(core): ship <data>/trust/extra roots to the guest as trust/extra.pem (#283)"
```

---

### Task 4: izba-init folds the extra roots into the guest anchors + bundle; fix the stale "MITM-only" comments

**Files:**
- Modify: `crates/izba-init/src/trust.rs` (constants, `build_anchor_pem`, tests)
- Modify: `crates/izba-init/src/main.rs:687-750` (`write_trust_anchor`)
- Modify: `crates/izba-init/src/exec.rs:122-125` (doc comment)
- Modify: `crates/izba-init/src/mounts.rs:18-20` (doc comment)

**Interfaces:**
- Consumes: the share file name `extra.pem` written by Task 3.
- Produces: `pub const EXTRA_FILE: &str = "extra.pem";`
- Produces: `pub fn build_anchor_pem(ca_pem: &str, extra_pem: Option<&str>) -> String`
  (izba CA first, then the extras, newline-separated; CA verbatim when `None`).
- Guest layout (unchanged paths, widened contents): `/etc/izba/ca.pem` = anchors
  (izba CA + extras — this is what `NODE_EXTRA_CA_CERTS`/`DENO_CERT` read, so
  the extras MUST be in it); `/etc/izba/ca-bundle.pem` = anchors + system roots;
  the Debian canonical bundle gets the anchors appended.

- [ ] **Step 1: Write the failing tests** (append to `mod tests` in `crates/izba-init/src/trust.rs`)

```rust
    #[test]
    fn anchor_pem_is_the_ca_alone_without_extras() {
        assert_eq!(build_anchor_pem("CA-PEM\n", None), "CA-PEM\n");
    }

    #[test]
    fn anchor_pem_is_ca_then_extras_newline_separated() {
        assert_eq!(
            build_anchor_pem("CA-PEM", Some("CORP-A\nCORP-B\n")),
            "CA-PEM\nCORP-A\nCORP-B\n",
            "izba CA first, then every extra root in shipped order"
        );
    }

    /// The AC's ordering contract end to end: izba CA, each extra PEM in
    /// order, then the system roots.
    #[test]
    fn combined_bundle_is_ca_then_extras_then_system() {
        let anchors = build_anchor_pem("CA-PEM\n", Some("CORP-A\nCORP-B\n"));
        assert_eq!(
            build_combined_bundle(&anchors, Some("SYS-ROOTS\n")),
            "CA-PEM\nCORP-A\nCORP-B\nSYS-ROOTS\n"
        );
    }

    #[test]
    fn extra_file_name_matches_the_host_contract() {
        assert_eq!(EXTRA_FILE, "extra.pem");
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p izba-init trust::tests`
Expected: compile error — `build_anchor_pem`, `EXTRA_FILE` not found.

- [ ] **Step 3: Implement**

In `crates/izba-init/src/trust.rs` add after `CA_FILE`:

```rust
/// Filename of the OPTIONAL host-installed extra roots inside the share
/// (`<data>/trust/extra/*.pem` concatenated by `sandbox::start`, #283).
/// Absent when the operator installed none.
pub const EXTRA_FILE: &str = "extra.pem";
```

and after `build_combined_bundle`:

```rust
/// The izba-added anchors: the izba CA first, then the host's extra roots
/// (already newline-joined by the host side). This is what lands in
/// `/etc/izba/ca.pem` — `NODE_EXTRA_CA_CERTS`/`DENO_CERT` read THIS file, so
/// the corporate roots must be in it, not only in the combined bundle.
pub fn build_anchor_pem(ca_pem: &str, extra_pem: Option<&str>) -> String {
    build_combined_bundle(ca_pem, extra_pem)
}
```

Update the module doc's first paragraph: "bakes the izba root CA — and any
host-installed extra roots (#283) — into the guest trust store so workload
tools trust izbad's MITM leaves AND the operator's private PKI. Delivered for
EVERY sandbox, bare or enforcing: a bare sandbox's TLS goes end-to-end, so the
guest store is the only place a corporate root can live."

In `crates/izba-init/src/main.rs` `write_trust_anchor`:
- Replace the doc comment's "Best-effort and no-op when the share has no
  `ca.pem` — a sandbox without HTTPS MITM ships no CA, and …" with: "The host
  writes `ca.pem` for every sandbox (bare or enforcing); a missing file is
  still tolerated (no-op) because the trust-env defaulting in `exec.rs` is
  gated on `ca-bundle.pem` existing, so absence cleanly disables the feature.
  Since #283 the share may also carry `extra.pem` (host-installed roots),
  folded in as izba CA → extras → system roots."
- Replace the inline comment `// ENOENT is the normal "no MITM for this
  sandbox" path; anything` with `// ENOENT means the host shipped no CA
  (not expected today); anything`.
- After `let ca_pem = match … ;` add:

```rust
    // Host-installed extra roots (#283): optional; absent ⇒ izba CA only.
    let share_extra = format!("/rootfs{}/{}", trust::TRUST_MOUNT, trust::EXTRA_FILE);
    let extra_pem = match std::fs::read_to_string(&share_extra) {
        Ok(p) => Some(p),
        Err(e) => {
            if e.kind() != std::io::ErrorKind::NotFound {
                eprintln!("izba-init: reading extra roots {share_extra}: {e}");
            }
            None
        }
    };
    let anchors = trust::build_anchor_pem(&ca_pem, extra_pem.as_deref());
```

- Then write `anchors` (not `ca_pem`) to `/rootfs/etc/izba/ca.pem`; pass
  `&anchors` to `build_combined_bundle`; append `anchors.as_bytes()` to the
  canonical Debian bundle. Update the two doc lines: "`/etc/izba/ca.pem` (the
  anchors: izba CA + extra roots, for runtimes that ADD roots)".

In `crates/izba-init/src/exec.rs:122-125` replace "Gates the trust-env
defaulting so only MITM-enabled sandboxes advertise the CA-bundle vars." with
"Gates the trust-env defaulting on the bundle existing (the host ships it for
every sandbox today; the gate keeps a CA-less boot from advertising a path
that isn't there)."

In `crates/izba-init/src/mounts.rs:18-20` replace "(e.g. the `izba-trust` CA
share, present only for MITM-enabled sandboxes)" with "(e.g. the `izba-trust`
CA share — attached for every sandbox today, but optional so a host that
ships no CA still boots)".

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p izba-init && cargo build -p izba-init --target x86_64-unknown-linux-musl --release`
Expected: all pass; static build succeeds.

- [ ] **Step 5: Gates + commit**

Run: `cargo clippy -p izba-init --all-targets -- -D warnings && cargo fmt --check`

```bash
git add crates/izba-init/src/trust.rs crates/izba-init/src/main.rs crates/izba-init/src/exec.rs crates/izba-init/src/mounts.rs
git commit -m "feat(init): fold host extra roots into the guest anchors and bundle; drop stale MITM-only wording (#283)"
```

---

### Task 5: `izba daemon status` reports the loaded extra CAs; README documents the directory + reload semantics

**Files:**
- Modify: `crates/izba-core/src/daemon/proto.rs:404-416` (`DaemonStatus`) and the fixture literal at `proto.rs:~725`
- Modify: `crates/izba-core/src/daemon/server.rs` (`Daemon` struct + `new` + the `DaemonRequest::Status` arm ~line 511)
- Modify: `crates/izba-cli/src/commands/daemon.rs:35-50` (`status`)
- Modify: `README.md:130-147` (the MITM/CA paragraph) + a new "Custom / corporate CAs" bullet after it
- Test: `crates/izba-core/src/daemon/proto.rs` (round-trip default test)

**Interfaces:**
- Consumes: `load_extra_cas` (Task 1).
- Produces: `DaemonStatus.extra_ca_files: Vec<String>` (`#[serde(default)]`, file names
  loaded at daemon start, in load order) and `DaemonStatus.trust_extra_dir: String`
  (`#[serde(default)]`, display path). Additive + defaulted ⇒ NO proto bump.
- Produces: `Daemon.extra_ca_files: Vec<String>` (private), captured in `Daemon::new`.

- [ ] **Step 1: Write the failing test** (in `proto.rs` `mod tests`, next to the existing `DaemonStatus` fixture)

```rust
    /// #283: a pre-#283 daemon's Status frame (no trust fields) must still
    /// deserialize — the fields are additive and defaulted, no proto bump.
    #[test]
    fn daemon_status_trust_fields_default_when_absent() {
        let json = serde_json::json!({
            "version": "x", "pid": 1, "uptime_ms": 0, "socket": "s", "sandboxes": []
        });
        let s: DaemonStatus = serde_json::from_value(json).unwrap();
        assert!(s.extra_ca_files.is_empty());
        assert_eq!(s.trust_extra_dir, "");
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p izba-core daemon_status_trust_fields_default_when_absent`
Expected: compile error — no field `extra_ca_files`.

- [ ] **Step 3: Implement**

`proto.rs` `DaemonStatus` — add after `sandboxes`:

```rust
    /// Host-installed extra CA files izbad loaded at start (`<data>/trust/extra`,
    /// #283), in load order. Empty = webpki-roots only. `serde(default)`: a
    /// pre-#283 daemon reads as "none loaded", which is the honest answer.
    #[serde(default)]
    pub extra_ca_files: Vec<String>,
    /// Display path of that directory, so `izba daemon status` can say where
    /// to put a CA. `serde(default)` for the same reason.
    #[serde(default)]
    pub trust_extra_dir: String,
```

Update the fixture literal at `proto.rs:~725` and the `server.rs:~511`
literal with `extra_ca_files: …, trust_extra_dir: …` (fixture: `vec![]` and
`String::new()`; server: `self.extra_ca_files.clone()` and
`crate::paths::display_path(&self.paths.trust_extra_dir())`).

`server.rs` — add to `Daemon`:

```rust
    /// File names loaded from `<data>/trust/extra` at daemon start (#283),
    /// for `Status`. Not authoritative state — a display record of what THIS
    /// process trusts; a changed directory needs a daemon restart.
    extra_ca_files: Vec<String>,
```

and in `Daemon::new`, capture the names: change `build_mitm_runtime` to
return `(Option<Arc<MitmRuntime>>, Vec<String>)` — the `Vec` is the loaded
names (empty on any failure path) — and destructure at the call site:
`let (mitm, extra_ca_files) = build_mitm_runtime(&paths, audit.clone());`,
storing `extra_ca_files` in the struct.

`crates/izba-cli/src/commands/daemon.rs` `status` — after `println!("socket: {}", s.socket);` add:

```rust
            if s.extra_ca_files.is_empty() {
                println!(
                    "trust: webpki roots only (drop corporate CA .pem files into {} — \
                     guests pick them up on their next start, izbad after `izba daemon stop`)",
                    s.trust_extra_dir
                );
            } else {
                println!(
                    "trust: webpki roots + {} extra CA file(s) from {}: {} \
                     (guests: on next start; izbad: reload with `izba daemon stop`)",
                    s.extra_ca_files.len(),
                    s.trust_extra_dir,
                    s.extra_ca_files.join(", ")
                );
            }
```

`README.md` — in the paragraph at lines 130-147:
- Replace the last sentence "A **bare** (non-enforcing) sandbox does NOT
  intercept TLS and ships no CA — connections dial straight through." with:
  "The CA is written into **every** sandbox, bare or enforcing; a **bare**
  (non-enforcing) sandbox simply never intercepts TLS — connections dial
  straight through end-to-end, so the guest's own trust store decides."
- Add a new bullet immediately after that paragraph:

```markdown
  **Custom / corporate CAs (TLS-inspecting proxies, internal registries and
  git hosts).** Drop the root certificate(s) as PEM files into
  `~/.local/share/izba/trust/extra/` (any `*.pem` / `*.crt`; loaded in
  file-name order). They are host-only — a guest can never write them — and
  they are honored on BOTH paths: every sandbox's guest trust store
  (`/etc/izba/ca.pem` + the combined bundle and trust-env vars above) gets
  them appended after the izba CA, so a bare sandbox's end-to-end TLS
  verifies; and `izbad`'s upstream verifier trusts them on top of the
  Mozilla roots, so an enforcing sandbox's re-originated connection verifies
  too. Reload semantics: a guest picks up changes on its next `izba start`;
  `izbad` reads the directory once at start — run `izba daemon stop` (the next
  command respawns it) and check `izba daemon status`, which lists the loaded
  files. A file that is not a valid PEM certificate refuses `izba start` and
  disables the firewall's HTTPS path (enforcing sandboxes fail closed) with
  the file named in the error — fix or remove it. The host OS trust store is
  NOT imported automatically; copy the roots you need.
```

- [ ] **Step 4: Run tests + the app gate**

Run: `cargo test -p izba-core daemon && cargo test -p izba-cli`
Expected: pass.

Run the app gate (DaemonStatus is a public core type; `views.rs` uses field
access, not a destructuring pattern, so it should compile unchanged — verify):
`cd app && npm ci && npm run build && npm run test && (cd src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test)`
Expected: green. (If `views.rs`'s `From<DaemonStatus>` uses an exhaustive
struct pattern, add the two fields to it.)

- [ ] **Step 5: Gates + commit**

Run the six workspace gates from CLAUDE.md.

```bash
git add crates/izba-core/src/daemon/proto.rs crates/izba-core/src/daemon/server.rs crates/izba-cli/src/commands/daemon.rs README.md
git commit -m "feat(cli): izba daemon status reports loaded extra CAs; document <data>/trust/extra and reload semantics (#283)"
```

---

### Task 6: KVM e2e — a private-CA TLS upstream from inside the guest, enforce OFF and ON, trusted vs untrusted

**Files:**
- Modify: `crates/izba-core/tests/integration.rs` (new helpers + one `#[test]`, placed after `observe_pinning_arm`'s block, ~line 2080)

**Interfaces:**
- Consumes: `izba_core::trust::{load_extra_cas, upstream_client_config}`;
  `Paths::trust_extra_dir`; existing helpers `want`, `TestBox`, `create_sandbox`,
  `start_sandbox`, `stop_sandbox`, `exec_collect`, `console_tail`,
  `EgressManager`, `MitmRuntime`, `CertCache`, `server_config_with_resolver`,
  `IzbaCa`, `AuditSink`; hickory-proto 0.26 (a normal dep of izba-core,
  visible to its integration tests).
- Design: TWO private CAs. `trusted-ca` is installed into `<data>/trust/extra/corp.pem`;
  `rogue-ca` is not. Two HTTPS upstreams on the host's LAN IP (same trick as
  `egress_http_via_stub`), one minted under each CA, named
  `trusted.izba.test` / `rogue.izba.test` via a fixed-answer test resolver.
  One boot per arm: OFF (no policy ⇒ AllowAll raw splice) and ON
  (policy allowing both names with `protocol: http` on their ports so the
  router's tier-1 gate terminates and re-originates through the production
  upstream config). Assertions: trusted body arrives; rogue fetch fails
  non-zero AND the body never arrives. Absence of the CA is the same fact as
  "rogue-ca is not in the directory" — one directory state proves both
  positive and negative per arm, halving the VM boots.

- [ ] **Step 1: Write the e2e** (it is red until Tasks 1-4 are merged; on this branch they already are, so it should go green on first run — the "fail first" evidence for this task is running it against `origin/main`'s behavior is impractical; instead run it ONCE with the `extra` install line commented out and confirm the `trusted` assertions fail, then restore the line)

Append to `crates/izba-core/tests/integration.rs`:

```rust
// ============================================================================
// #283 — host-installed custom CA bundles
// ============================================================================

/// Answers `A` for the names in `map` (else NOERROR/empty), any other qtype
/// NOERROR/empty. Stands in for izbad's system resolver so a test hostname can
/// point at the host's LAN IP without touching real DNS.
struct FixedAResolver {
    map: Vec<(String, std::net::Ipv4Addr)>,
}

impl izba_core::daemon::egress::dns::Resolver for FixedAResolver {
    fn handle(&self, query: &[u8]) -> anyhow::Result<Vec<u8>> {
        use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
        use hickory_proto::rr::{rdata::A, RData, Record, RecordType};
        let req = Message::from_vec(query)?;
        let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
        for q in &req.queries {
            resp.add_query(q.clone());
            if q.query_type() != RecordType::A {
                continue;
            }
            let qname = q.name().to_utf8();
            let qname = qname.trim_end_matches('.');
            if let Some((_, ip)) = self
                .map
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(qname))
            {
                resp.add_answer(Record::from_rdata(q.name().clone(), 60, RData::A(A(*ip))));
            }
        }
        resp.metadata.recursion_desired = req.recursion_desired;
        resp.metadata.recursion_available = true;
        resp.metadata.response_code = ResponseCode::NoError;
        Ok(resp.to_vec()?)
    }
}

/// The host's LAN-facing IP (never loopback: 127/8 is excluded from the
/// guest's REDIRECT by design and hard-denied by the router).
fn host_lan_ip() -> std::net::Ipv4Addr {
    let probe = std::net::UdpSocket::bind(("0.0.0.0", 0)).unwrap();
    probe.connect(("8.8.8.8", 80)).unwrap();
    match probe.local_addr().unwrap().ip() {
        std::net::IpAddr::V4(v4) => v4,
        other => panic!("expected an IPv4 LAN address, got {other}"),
    }
}

/// A minimal HTTPS/1.x upstream: TLS under `ca` (leaf minted per SNI by the
/// same resolver the MITM uses), answers every request with `body`. Bound on
/// the host LAN IP so the guest can reach it. Returns the port.
fn spawn_private_ca_https(
    rt: &tokio::runtime::Runtime,
    ca: izba_core::daemon::egress::mitm::IzbaCa,
    ip: std::net::Ipv4Addr,
    body: &'static str,
) -> u16 {
    use izba_core::daemon::egress::mitm::{server_config_with_resolver, CertCache};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::TlsAcceptor;

    let acceptor = TlsAcceptor::from(Arc::new(server_config_with_resolver(Arc::new(
        CertCache::new(ca),
    ))));
    let listener = rt.block_on(tokio::net::TcpListener::bind((ip, 0))).unwrap();
    let port = listener.local_addr().unwrap().port();
    rt.spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                // Read the request head (until the blank line) then answer.
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") && tls.read_exact(&mut b).await.is_ok() {
                    head.push(b[0]);
                    if head.len() > 16 * 1024 {
                        break;
                    }
                }
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = tls.write_all(resp.as_bytes()).await;
                let _ = tls.flush().await;
                let _ = tls.shutdown().await;
            });
        }
    });
    port
}

/// `wget` the URL from inside the guest under the exec-default trust env
/// (SSL_CERT_FILE=/etc/izba/ca-bundle.pem). Returns (exit ok, stdout+stderr).
fn guest_wget(paths: &Paths, name: &str, url: &str) -> (bool, String) {
    let cmd = format!("wget -T 20 -qO- {url}");
    match exec_collect(paths, name, &["sh", "-lc", &cmd], None) {
        Ok((status, out, err)) => (
            matches!(status, ExitStatus::Code(0)),
            format!("$ {cmd}\n-> {status:?}\n{out}{err}"),
        ),
        Err((kind, msg)) => (false, format!("$ {cmd}\n-> exec rejected ({kind:?}): {msg}")),
    }
}

/// Which egress posture an arm boots under.
#[derive(Clone, Copy)]
enum CaArm {
    /// No policy ⇒ AllowAll ⇒ raw TCP splice; the GUEST verifies the cert.
    EnforceOff,
    /// Enforcing policy with `protocol: http` on the upstream ports ⇒ the
    /// router terminates at the MITM and IZBAD verifies the upstream.
    EnforceOn,
}

/// Boot one arm and fetch from both upstreams. Returns
/// ((trusted_ok, trusted_out), (rogue_ok, rogue_out)).
fn run_custom_ca_arm(
    env: &TestEnv,
    tb: &mut TestBox,
    rt: &tokio::runtime::Runtime,
    arm: CaArm,
    resolver: std::sync::Arc<dyn izba_core::daemon::egress::dns::Resolver>,
    trusted_port: u16,
    rogue_port: u16,
) -> ((bool, String), (bool, String)) {
    use izba_core::daemon::egress::audit::AuditSink;
    use izba_core::daemon::egress::mitm::CertCache;
    use izba_core::daemon::egress::mitm_runtime::MitmRuntime;
    use izba_core::daemon::egress::EgressManager;
    use std::sync::Arc;

    let name = match arm {
        CaArm::EnforceOff => "customca-off",
        CaArm::EnforceOn => "customca-on",
    };
    let ws = tb.workspace(name);
    create_sandbox(env, tb, name, &ws);

    let audit = AuditSink::new(tb.paths.clone());
    let mitm = match arm {
        CaArm::EnforceOff => None,
        CaArm::EnforceOn => {
            std::fs::write(
                izba_core::daemon::egress::config::EgressPolicyConfig::path_in(
                    &tb.paths.sandbox_dir(name),
                ),
                format!(
                    "enforce: true\nallow:\n  - host: trusted.izba.test\n    ports: [{trusted_port}]\n    protocol: http\n  - host: rogue.izba.test\n    ports: [{rogue_port}]\n    protocol: http\n"
                ),
            )
            .expect("write policy.yaml");
            let _ = rustls::crypto::ring::default_provider().install_default();
            let ca = izba_core::ca::load_or_create(&tb.paths.ca_dir()).expect("izba CA");
            // THE PRODUCTION upstream builder — reads <data>/trust/extra.
            let extra = izba_core::trust::load_extra_cas(&tb.paths.trust_extra_dir())
                .expect("load extra CAs");
            assert_eq!(extra.len(), 1, "exactly corp.pem is installed");
            Some(Arc::new(
                MitmRuntime::start(
                    Arc::new(CertCache::new(ca)),
                    izba_core::trust::upstream_client_config(&extra),
                    audit.clone(),
                )
                .expect("start MITM runtime"),
            ))
        }
    };
    let _ = rt; // the upstreams live on the caller's runtime
    let mgr = EgressManager::new(resolver, mitm, audit);
    mgr.ensure_listening(&tb.paths, name, &tb.paths.run_dir(name))
        .expect("bind vsock_1027 listener");
    if let Err(e) = start_sandbox(env, tb, name) {
        mgr.stop(name, &tb.paths.run_dir(name));
        panic!(
            "boot of {name:?} failed: {e:#}\nconsole tail:\n{}",
            console_tail(&tb.paths, name)
        );
    }

    // Warm-up: the first egress dial after boot can settle a beat late.
    let mut trusted = (false, String::new());
    for _ in 0..5 {
        trusted = guest_wget(&tb.paths, name, &format!("https://trusted.izba.test:{trusted_port}/"));
        if trusted.0 {
            break;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    let rogue = guest_wget(&tb.paths, name, &format!("https://rogue.izba.test:{rogue_port}/"));

    stop_sandbox(tb, name);
    mgr.stop(name, &tb.paths.run_dir(name));
    (trusted, rogue)
}

/// #283 acceptance: a TLS upstream signed by a private CA installed in
/// `<data>/trust/extra/` is reachable from the guest with enforcement OFF
/// (raw splice — the GUEST trust store decides) and ON (izbad terminates and
/// re-originates — IZBAD's upstream verifier decides); an upstream signed by
/// a CA that is NOT in the directory is refused on both paths (fails closed:
/// non-zero exit AND no body), proving the trust is exactly the directory's
/// contents and nothing wider.
#[test]
fn custom_ca_trusted_in_guest_and_at_izbad_upstream_real_vm() {
    let Some(env) = want() else { return };
    let _ = rustls::crypto::ring::default_provider().install_default();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut tb = TestBox::new();

    let ip = host_lan_ip();
    let trusted_ca = izba_core::daemon::egress::mitm::IzbaCa::generate().unwrap();
    let rogue_ca = izba_core::daemon::egress::mitm::IzbaCa::generate().unwrap();
    std::fs::create_dir_all(tb.paths.trust_extra_dir()).unwrap();
    std::fs::write(tb.paths.trust_extra_dir().join("corp.pem"), trusted_ca.cert_pem()).unwrap();

    let trusted_port = spawn_private_ca_https(&rt, trusted_ca, ip, "TRUSTED-CA-BODY");
    let rogue_port = spawn_private_ca_https(&rt, rogue_ca, ip, "ROGUE-CA-BODY");
    let resolver: std::sync::Arc<dyn izba_core::daemon::egress::dns::Resolver> =
        std::sync::Arc::new(FixedAResolver {
            map: vec![("trusted.izba.test".into(), ip), ("rogue.izba.test".into(), ip)],
        });

    for arm in [CaArm::EnforceOff, CaArm::EnforceOn] {
        let ((t_ok, t_out), (r_ok, r_out)) = run_custom_ca_arm(
            &env,
            &mut tb,
            &rt,
            arm,
            std::sync::Arc::clone(&resolver),
            trusted_port,
            rogue_port,
        );
        let label = match arm {
            CaArm::EnforceOff => "enforce OFF",
            CaArm::EnforceOn => "enforce ON",
        };
        assert!(t_ok, "[{label}] upstream under the INSTALLED CA must be reachable:\n{t_out}");
        assert!(
            t_out.contains("TRUSTED-CA-BODY"),
            "[{label}] trusted body must arrive:\n{t_out}"
        );
        assert!(!r_ok, "[{label}] upstream under a CA NOT installed must fail:\n{r_out}");
        assert!(
            !r_out.contains("ROGUE-CA-BODY"),
            "[{label}] rogue body must never arrive (fail closed):\n{r_out}"
        );
    }
}
```

Check before running: `ExitStatus`, `TestEnv`, `Duration`, `Paths` are
already imported at the top of `integration.rs` (they are used by
`guest_https_fetch` / `observe_pinning_arm`); `rustls`, `tokio_rustls`,
`hickory_proto` are `izba-core` deps and therefore visible to its integration
tests; `IzbaCa`, `server_config_with_resolver`, `CertCache` are `pub` in
`izba_core::daemon::egress::mitm` (used by `egress_inspect.rs`). If
`Message::new`'s signature or the `metadata` field names differ from
`sys_resolver.rs:96-105`, copy exactly what that file does — it is the
in-tree hickory 0.26 usage.

- [ ] **Step 2: Compile, then run it red once** (unsandboxed, KVM)

Run: `cargo test -p izba-core --test integration --no-run`
Expected: compiles.

Temporarily comment out the `std::fs::write(tb.paths.trust_extra_dir().join("corp.pem"), …)` line and change the `assert_eq!(extra.len(), 1, …)` to `assert!(extra.is_empty())`; run
`IZBA_INTEGRATION=1 cargo test -p izba-core --test integration -- --test-threads=1 custom_ca`
Expected: FAILS at `[enforce OFF] upstream under the INSTALLED CA must be reachable` (wget: certificate verification error). Restore both lines.

- [ ] **Step 3: Run it green**

Run: `IZBA_INTEGRATION=1 cargo test -p izba-core --test integration -- --test-threads=1 custom_ca`
Expected: 1 passed. Then run the neighbouring MITM tests that Task 2 rewired
to the production builder:
`IZBA_INTEGRATION=1 cargo test -p izba-core --test integration -- --test-threads=1 mitm pinning`
Expected: pass.

- [ ] **Step 4: Gates + commit**

Run: `cargo clippy -p izba-core --all-targets -- -D warnings && cargo fmt --check`

```bash
git add crates/izba-core/tests/integration.rs
git commit -m "test(core): KVM e2e — private-CA upstream trusted in-guest and at izbad, refused when uninstalled (#283)"
```

---

### Task 7: Delivery — full gates, push, PR, follow-up issue, CI iteration

**Files:** none new.

- [ ] **Step 1: Run all six workspace gates + the app gate + the two KVM suites once more**

```bash
[ -f .cargo-env ] && source .cargo-env
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo build -p izba-init --target x86_64-unknown-linux-musl --release
cargo check  --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli
cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings
(cd app && npm ci && npm run build && npm run test && (cd src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test))
IZBA_INTEGRATION=1 cargo test -p izba-core --test integration -- --test-threads=1 custom_ca mitm
IZBA_INTEGRATION=1 cargo test -p izba-cli --test daemon_e2e -- --test-threads=1
```

- [ ] **Step 2: Rebase on `origin/main` if behind, push, open the PR (ready, never draft)**

```bash
git fetch origin && git rebase origin/main
git push -u origin feat/host-custom-ca-bundles
gh pr create --title "feat: honor host-installed custom CA bundles in the guest and at izbad's upstream (#283)" --body "$(cat <<'EOF'
Closes #283.

## What
- New host-only `<data>/trust/extra/*.pem|*.crt` (sorted by file name). One loader (`izba_core::trust`), two consumers.
- Guest: `sandbox::start` ships the concatenation as `trust/extra.pem` on the existing read-only `izba-trust` share; `izba-init` folds it in as izba CA → extras → system roots (`/etc/izba/ca.pem` now carries the extras too, so `NODE_EXTRA_CA_CERTS`/`DENO_CERT` see them). Every sandbox, bare or enforcing; picked up on the next start; a stale `extra.pem` is removed when the directory empties.
- izbad: the upstream `ClientConfig` root store is webpki-roots + the extras (loaded at daemon start; `izba daemon stop` to reload). A corrupt file refuses `start` and disables the MITM (fail closed), naming the file.
- `izba daemon status` prints the loaded files + the directory; README documents the directory and reload semantics; stale "CA only for MITM sandboxes" wording fixed.
- No `DAEMON_PROTO_VERSION` bump: the only wire change is two `#[serde(default)]` fields on `DaemonStatus`.

## Tests
- Unit: loader (ordering, extensions, multi-cert, corrupt ⇒ error naming the file), upstream root store (count + a duplex TLS handshake that verifies ONLY with the extra CA), `start` share contents/removal/refusal, guest bundle ordering, `DaemonStatus` back-compat.
- KVM e2e `custom_ca_trusted_in_guest_and_at_izbad_upstream_real_vm`: two private CAs, one installed; enforce OFF and ON; the installed one's upstream is reachable, the other is refused (non-zero AND no body) on both paths.

## Deferred
- Auto-import of the host OS trust store (rustls-native-certs): explicit directory only, per the PM recommendation on #283 — follow-up filed as #<n>.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 3: File the deferred follow-up and link it in the PR body**

```bash
gh issue create -R Lupus/izba --title "Optionally auto-import the host OS trust store into <data>/trust/extra semantics (rustls-native-certs)" --body "Follow-up to #283, which ships the explicit \`<data>/trust/extra/\` directory only. If demand appears: an opt-in setting that additionally imports the host OS trust store (rustls-native-certs) into both the guest bundle and izbad's upstream verifier. Deliberately NOT default: deterministic, reviewable, cross-platform trust with no surprise widening."
gh project item-add 1 --owner Lupus --url <issue-url>
gh pr edit <pr> --body "...replace #<n> with the real number..."
```

- [ ] **Step 4: Dispatch the dev installer build while CI runs**

Run (unsandboxed): `bash hack/devbuild.sh` — record the exact main-checkout `dist/local/<ts>-<sha>/` path it prints.

- [ ] **Step 5: Iterate on CI to CLEAN** — all required checks green, SonarCloud
quality gate passing, Greptile 5/5 with no unresolved actionable comments (use
the `greploop` skill). Re-run only genuinely infra-flaky jobs. Report the PR
link, the summary, and the installer path with paste-ready install commands.

---

## Self-review

**Spec coverage (issue #283 acceptance criteria):**
- Host-only extra-CA dir, documented, guest can't write it → Task 1 (dir), Task 5 (README), never shared as a directory (Task 3 ships a copy on a RO share).
- Every sandbox's guest bundle = izba CA + each extra PEM regardless of enforcement, unit-tested for contents + order → Task 3 (shipped for every start; no enforcement gate) + Task 4 (`combined_bundle_is_ca_then_extras_then_system`).
- izbad upstream root store = webpki + extras, unit-tested → Task 2.
- KVM e2e enforce OFF reachable; enforce ON reachable; UNREACHABLE when absent (both) → Task 6 (two-CA design covers present + absent per arm).
- `izba status` and/or docs state the location + reload semantics → Task 5 (`izba daemon status` line + README).
- Stale "CA only for MITM" comments + README:143-145 corrected → Task 4 (init comments) + Task 5 (README) + Task 3 (`ca_present` comment).
- INVEST open question (OS trust-store auto-import) → settled as deferred; Task 7 files the follow-up.

**Placeholder scan:** the only `<n>`/`<pr>`/`<issue-url>` tokens are in Task 7's shell commands and are filled from that step's own output.

**Type consistency:** `ExtraCaFile { name, pem, certs }` (Task 1) is what Tasks 2, 3, 5 consume; `load_extra_cas(&Path) -> Result<Vec<ExtraCaFile>>` everywhere; `guest_extra_pem(&[ExtraCaFile]) -> String` (Task 1 ↔ Task 3); `upstream_client_config(&[ExtraCaFile]) -> Arc<ClientConfig>` (Task 2 ↔ server.rs ↔ Task 6); share file `extra.pem` (Task 3 ↔ `EXTRA_FILE` Task 4); `DaemonStatus.{extra_ca_files, trust_extra_dir}` (Task 5 proto ↔ server ↔ CLI).
