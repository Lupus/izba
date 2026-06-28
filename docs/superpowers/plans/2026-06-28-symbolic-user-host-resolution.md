# Host-side symbolic `USER` resolution — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve an image's symbolic `USER` (e.g. `node`, `nonroot`, `1000:wheel`) to a numeric `(uid, gid)` host-side, so the workload runs as — and `/workspace` is owned by — the image's intended user instead of falling back to root.

**Architecture:** Capture the image's `/etc/passwd` + `/etc/group` during the flatten pipeline into the content-addressed image store; resolve the declared `USER` against them in `resolve_process_user`; feed the numeric ids into the existing `process.user` + Option-A userns transposition. Pure, unit-testable logic in `izba-core`; zero guest changes.

**Tech Stack:** Rust, `oci_client`, `oci_spec`, `tar` crate, `serde_json`; tests with `tempfile`.

## Global Constraints

- Six workspace gates must stay green: `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check`, the musl static build, and both `x86_64-pc-windows-gnu` `cargo check`/`clippy` gates. (`source .cargo-env` first if present.)
- TDD: failing test first, minimal impl, green, commit. Conventional commits (`feat(core): …`).
- Numeric and root `USER` behaviour MUST stay byte-for-byte unchanged.
- `izba-core` config-merge layer is kept free of I/O so it stays exhaustively unit-tested — new resolution logic is pure functions over passed-in strings.
- No new dependencies. (`tar`, `serde_json`, `oci_client`, `oci_spec` already in `izba-core`.)
- Never silently downgrade security: an unresolvable symbolic `USER` keeps the existing loud `eprintln!("warning: sandbox '{name}': …")` root fallback.

---

### Task 1: passwd/group parsing + `UserDb::resolve`

**Files:**
- Modify: `crates/izba-core/src/image/runtime_config.rs` (add below `parse_numeric_user`, ~line 232)
- Test: same file's `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `pub struct PasswdEntry { pub name: String, pub uid: u32, pub gid: u32 }`
  - `pub struct GroupEntry { pub name: String, pub gid: u32 }`
  - `pub fn parse_passwd(content: &str) -> Vec<PasswdEntry>`
  - `pub fn parse_group(content: &str) -> Vec<GroupEntry>`
  - `pub struct UserDb { pub passwd: Vec<PasswdEntry>, pub group: Vec<GroupEntry> }`
  - `impl UserDb { pub fn from_files(passwd: Option<&str>, group: Option<&str>) -> Self; pub fn resolve(&self, spec: &str) -> Option<(u32, u32)> }`

- [ ] **Step 1: Write the failing tests**

```rust
    // ---- passwd/group parsing + UserDb::resolve ----

    #[test]
    fn parse_passwd_basic_and_skips_junk() {
        let p = parse_passwd(
            "root:x:0:0:root:/root:/bin/sh\n\
             # a comment\n\
             \n\
             node:x:1000:1000:Node:/home/node:/bin/sh\n\
             short:x:1\n",
        );
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].name, "root");
        assert_eq!((p[1].name.as_str(), p[1].uid, p[1].gid), ("node", 1000, 1000));
    }

    #[test]
    fn parse_group_basic_and_skips_junk() {
        let g = parse_group("root:x:0:\nwheel:x:10:node\n#c\n\nbad:x\n");
        assert_eq!(g.len(), 2);
        assert_eq!((g[1].name.as_str(), g[1].gid), ("wheel", 10));
    }

    #[test]
    fn userdb_resolves_name_to_uid_and_primary_gid() {
        let db = UserDb::from_files(Some("node:x:1000:1000::/:/bin/sh\n"), None);
        assert_eq!(db.resolve("node"), Some((1000, 1000)));
    }

    #[test]
    fn userdb_resolves_name_colon_group_name() {
        let db = UserDb::from_files(
            Some("node:x:1000:1000::/:/bin/sh\n"),
            Some("wheel:x:10:\n"),
        );
        assert_eq!(db.resolve("node:wheel"), Some((1000, 10)));
    }

    #[test]
    fn userdb_numeric_uid_does_not_consult_passwd() {
        // Pure-numeric spec keeps docker's default gid 0 even if passwd has 1000.
        let db = UserDb::from_files(Some("node:x:1000:1000::/:/bin/sh\n"), None);
        assert_eq!(db.resolve("1000"), Some((1000, 0)));
        assert_eq!(db.resolve("1000:1001"), Some((1000, 1001)));
    }

    #[test]
    fn userdb_unknown_name_or_group_is_none() {
        let db = UserDb::from_files(Some("node:x:1000:1000::/:/bin/sh\n"), Some("wheel:x:10:\n"));
        assert_eq!(db.resolve("ghost"), None);
        assert_eq!(db.resolve("node:ghostgroup"), None);
    }

    #[test]
    fn userdb_name_colon_numeric_gid() {
        let db = UserDb::from_files(Some("node:x:1000:1000::/:/bin/sh\n"), None);
        assert_eq!(db.resolve("node:42"), Some((1000, 42)));
    }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p izba-core --lib image::runtime_config::tests::userdb 2>&1 | tail -20`
Expected: FAIL — `cannot find function/type` for `parse_passwd`/`UserDb`.

- [ ] **Step 3: Implement the pure resolver**

Insert after `parse_numeric_user` (after line ~232):

```rust
/// One `/etc/passwd` row reduced to the fields izba's USER resolution needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswdEntry {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
}

/// One `/etc/group` row reduced to `(name, gid)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupEntry {
    pub name: String,
    pub gid: u32,
}

/// Parse `/etc/passwd` content into entries. Standard 7-field colon format;
/// blank lines, `#` comments, and rows whose name/uid/gid don't parse are
/// skipped (a malformed image passwd never aborts a launch).
pub fn parse_passwd(content: &str) -> Vec<PasswdEntry> {
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim_end();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let mut f = line.split(':');
            let name = f.next()?;
            let _passwd = f.next()?;
            let uid = f.next()?.parse().ok()?;
            let gid = f.next()?.parse().ok()?;
            if name.is_empty() {
                return None;
            }
            Some(PasswdEntry { name: name.to_string(), uid, gid })
        })
        .collect()
}

/// Parse `/etc/group` content into `(name, gid)` entries (4-field colon
/// format; same skip rules as [`parse_passwd`]).
pub fn parse_group(content: &str) -> Vec<GroupEntry> {
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim_end();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let mut f = line.split(':');
            let name = f.next()?;
            let _passwd = f.next()?;
            let gid = f.next()?.parse().ok()?;
            if name.is_empty() {
                return None;
            }
            Some(GroupEntry { name: name.to_string(), gid })
        })
        .collect()
}

/// The image's user databases (`/etc/passwd` + `/etc/group`), used to resolve a
/// symbolic `USER` host-side exactly as docker/containerd do (against the image
/// rootfs at create time). An empty db (legacy cache / image without passwd)
/// resolves no names, so symbolic users fall back to the loud root path.
#[derive(Debug, Clone, Default)]
pub struct UserDb {
    pub passwd: Vec<PasswdEntry>,
    pub group: Vec<GroupEntry>,
}

impl UserDb {
    /// Build from raw file contents (each `None` when the image lacked it).
    pub fn from_files(passwd: Option<&str>, group: Option<&str>) -> Self {
        UserDb {
            passwd: passwd.map(parse_passwd).unwrap_or_default(),
            group: group.map(parse_group).unwrap_or_default(),
        }
    }

    /// Resolve a docker `user[:group]` spec to `(uid, gid)`, or `None` when any
    /// component is a name absent from the db. Pure-numeric components never
    /// consult the db (docker's numeric default gid is 0), matching
    /// [`parse_numeric_user`].
    pub fn resolve(&self, spec: &str) -> Option<(u32, u32)> {
        let (user_part, group_part) = match spec.split_once(':') {
            Some((u, g)) => (u, Some(g)),
            None => (spec, None),
        };
        // uid + the user's primary gid (used when no explicit group is given).
        let (uid, primary_gid) = match user_part.parse::<u32>() {
            Ok(uid) => (uid, 0), // numeric: docker default gid 0, no passwd lookup
            Err(_) => {
                let e = self.passwd.iter().find(|e| e.name == user_part)?;
                (e.uid, e.gid)
            }
        };
        let gid = match group_part {
            None => primary_gid,
            Some(g) => match g.parse::<u32>() {
                Ok(gid) => gid,
                Err(_) => self.group.iter().find(|e| e.name == g)?.gid,
            },
        };
        Some((uid, gid))
    }
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p izba-core --lib image::runtime_config::tests::userdb && cargo test -p izba-core --lib image::runtime_config::tests::parse_passwd image::runtime_config::tests::parse_group`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/image/runtime_config.rs
git commit -m "feat(core): parse image passwd/group and resolve user[:group]"
```

---

### Task 2: `resolve_process_user` consults the `UserDb`

**Files:**
- Modify: `crates/izba-core/src/image/runtime_config.rs` (`resolve_process_user`, ~lines 234-262)
- Test: same file

**Interfaces:**
- Consumes: `UserDb` (Task 1).
- Produces: new signature `pub fn resolve_process_user(declared: Option<&str>, db: &UserDb) -> ((u32, u32), Option<String>)`.

- [ ] **Step 1: Update existing tests + add resolution tests**

The current tests call `resolve_process_user(Some("node"))`. Update each call to pass a db, and add the resolved-symbolic case. Replace the whole `// ---- resolve_process_user …` test block with:

```rust
    // ---- resolve_process_user (config.json USER -> (uid,gid) + loud warning) ----

    fn db_with_node() -> UserDb {
        UserDb::from_files(
            Some("root:x:0:0::/root:/bin/sh\nnode:x:1000:1000::/home/node:/bin/sh\n"),
            Some("node:x:1000:\nwheel:x:10:\n"),
        )
    }

    #[test]
    fn resolve_process_user_none_is_silent_root() {
        assert_eq!(resolve_process_user(None, &UserDb::default()), ((0, 0), None));
    }

    #[test]
    fn resolve_process_user_empty_is_silent_root() {
        assert_eq!(resolve_process_user(Some(""), &UserDb::default()), ((0, 0), None));
    }

    #[test]
    fn resolve_process_user_numeric_is_silent() {
        assert_eq!(resolve_process_user(Some("1000"), &UserDb::default()), ((1000, 0), None));
        assert_eq!(
            resolve_process_user(Some("1000:1001"), &UserDb::default()),
            ((1000, 1001), None)
        );
    }

    #[test]
    fn resolve_process_user_symbolic_resolves_from_db() {
        assert_eq!(resolve_process_user(Some("node"), &db_with_node()), ((1000, 1000), None));
    }

    #[test]
    fn resolve_process_user_partly_symbolic_resolves_group() {
        assert_eq!(resolve_process_user(Some("1000:wheel"), &db_with_node()), ((1000, 10), None));
    }

    #[test]
    fn resolve_process_user_unresolvable_is_loud_root() {
        let ((uid, gid), warn) = resolve_process_user(Some("ghost"), &db_with_node());
        assert_eq!((uid, gid), (0, 0));
        assert!(warn.expect("must warn").contains("ghost"));
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p izba-core --lib image::runtime_config::tests::resolve_process_user 2>&1 | tail -20`
Expected: FAIL — arity mismatch / `db_with_node` unused-then-used.

- [ ] **Step 3: Update the implementation**

Replace `resolve_process_user` (and its doc comment) with:

```rust
/// Resolve an image's declared `USER` to a numeric `(uid, gid)` for config.json,
/// plus an optional loud warning.
///
/// - `None` / `Some("")` -> `((0,0), None)` (silent root).
/// - fully numeric (`"1000"`, `"1000:1001"`) -> resolved pair, no warning.
/// - symbolic (`"node"`, `"1000:wheel"`) resolved against `db` (the image's
///   `/etc/passwd`+`/etc/group`) -> resolved pair, no warning.
/// - symbolic but unresolvable (name absent from the image's passwd/group, or a
///   legacy cache with no captured db) -> `((0,0), Some(msg))` naming the USER.
///   izba never silently downgrades security, so the fallback is loud.
pub fn resolve_process_user(declared: Option<&str>, db: &UserDb) -> ((u32, u32), Option<String>) {
    match declared {
        None | Some("") => ((0, 0), None),
        Some(u) => match db.resolve(u) {
            Some(ids) => (ids, None),
            None => (
                (0, 0),
                Some(format!(
                    "image USER '{u}' could not be resolved against the image's /etc/passwd \
                     — running the workload as root (uid 0)"
                )),
            ),
        },
    }
}
```

Note: `db.resolve` already handles numeric specs without consulting the db, so the numeric fast-path stays exact.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p izba-core --lib image::runtime_config`
Expected: PASS (all runtime_config tests).

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/image/runtime_config.rs
git commit -m "feat(core): resolve symbolic USER against image passwd in resolve_process_user"
```

---

### Task 3: image store — persist/load captured passwd & group

**Files:**
- Modify: `crates/izba-core/src/image/store.rs`
- Test: same file's `#[cfg(test)] mod tests`

**Interfaces:**
- Produces:
  - `pub fn passwd_path(&self, digest: &str) -> PathBuf`
  - `pub fn group_path(&self, digest: &str) -> PathBuf`
  - `pub fn load_user_dbs(&self, digest: &str) -> Result<(Option<String>, Option<String>)>`
  - `pub fn persist_user_dbs(&self, digest: &str, passwd: Option<&[u8]>, group: Option<&[u8]>) -> Result<()>`

- [ ] **Step 1: Write the failing tests**

Add inside `mod tests`:

```rust
    #[test]
    fn user_db_paths() {
        let paths = Paths::with_root("/data/izba".into());
        let store = ImageStore::new(&paths);
        assert_eq!(
            store.passwd_path("sha256:abc"),
            PathBuf::from("/data/izba/images/sha256-abc/passwd")
        );
        assert_eq!(
            store.group_path("sha256:abc"),
            PathBuf::from("/data/izba/images/sha256-abc/group")
        );
    }

    #[test]
    fn user_dbs_round_trip() {
        let (_tmp, paths) = setup();
        let store = ImageStore::new(&paths);
        store
            .publish(DIGEST, |staging| {
                fs::write(staging.join("rootfs.erofs"), b"erofs")?;
                Ok(())
            })
            .unwrap();
        store
            .persist_user_dbs(DIGEST, Some(b"node:x:1000:1000::/:/bin/sh\n"), Some(b"wheel:x:10:\n"))
            .unwrap();
        let (passwd, group) = store.load_user_dbs(DIGEST).unwrap();
        assert!(passwd.unwrap().contains("node"));
        assert_eq!(group.unwrap(), "wheel:x:10:\n");
    }

    #[test]
    fn user_dbs_absent_is_none() {
        let (_tmp, paths) = setup();
        let store = ImageStore::new(&paths);
        store
            .publish(DIGEST, |staging| {
                fs::write(staging.join("rootfs.erofs"), b"erofs")?;
                Ok(())
            })
            .unwrap();
        assert_eq!(store.load_user_dbs(DIGEST).unwrap(), (None, None));
    }

    #[test]
    fn persist_user_dbs_skips_none_components() {
        let (_tmp, paths) = setup();
        let store = ImageStore::new(&paths);
        store
            .publish(DIGEST, |staging| {
                fs::write(staging.join("rootfs.erofs"), b"erofs")?;
                Ok(())
            })
            .unwrap();
        store.persist_user_dbs(DIGEST, Some(b"x:x:1:1::/:/x\n"), None).unwrap();
        let (passwd, group) = store.load_user_dbs(DIGEST).unwrap();
        assert!(passwd.is_some());
        assert!(group.is_none(), "no group file written when group is None");
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p izba-core --lib image::store::tests::user 2>&1 | tail -20`
Expected: FAIL — `passwd_path`/`load_user_dbs` not found.

- [ ] **Step 3: Implement**

Add methods inside `impl<'a> ImageStore<'a>` (after `persist_config`, ~line 67):

```rust
    /// Path of the image's captured `/etc/passwd` (absent for legacy caches).
    pub fn passwd_path(&self, digest: &str) -> PathBuf {
        self.paths.image_dir(digest).join("passwd")
    }

    /// Path of the image's captured `/etc/group` (absent for legacy caches).
    pub fn group_path(&self, digest: &str) -> PathBuf {
        self.paths.image_dir(digest).join("group")
    }

    /// Load the captured `(passwd, group)` contents for `digest`. Each is `None`
    /// when absent — images cached before passwd capture, or images shipping no
    /// such file. A non-`NotFound` read error propagates as `Err`.
    pub fn load_user_dbs(&self, digest: &str) -> Result<(Option<String>, Option<String>)> {
        let read_opt = |path: PathBuf| -> Result<Option<String>> {
            match fs::read_to_string(&path) {
                Ok(s) => Ok(Some(s)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e).with_context(|| format!("failed to read {}", path.display())),
            }
        };
        Ok((
            read_opt(self.passwd_path(digest))?,
            read_opt(self.group_path(digest))?,
        ))
    }

    /// Atomically persist the captured `passwd`/`group` for an already-published
    /// `digest`. A `None` component writes no file. Temp-file + rename per file,
    /// mirroring [`persist_config`]. The image dir must already exist.
    pub fn persist_user_dbs(
        &self,
        digest: &str,
        passwd: Option<&[u8]>,
        group: Option<&[u8]>,
    ) -> Result<()> {
        let dir = self.paths.image_dir(digest);
        let write_atomic = |bytes: &[u8], dst: PathBuf| -> Result<()> {
            let mut tmp = tempfile::Builder::new()
                .prefix(".userdb-")
                .tempfile_in(&dir)
                .with_context(|| format!("failed to stage user db in {}", dir.display()))?;
            std::io::Write::write_all(&mut tmp, bytes).context("failed to write staged user db")?;
            tmp.persist(&dst)
                .with_context(|| format!("failed to publish {}", dst.display()))?;
            Ok(())
        };
        if let Some(p) = passwd {
            write_atomic(p, self.passwd_path(digest))?;
        }
        if let Some(g) = group {
            write_atomic(g, self.group_path(digest))?;
        }
        Ok(())
    }
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p izba-core --lib image::store`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/image/store.rs
git commit -m "feat(core): cache image passwd/group in the image store"
```

---

### Task 4: extract passwd/group during flatten and capture in `publish_image`

**Files:**
- Modify: `crates/izba-core/src/image/mod.rs`
- Test: same file's `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: `ImageStore::persist_user_dbs` (Task 3).
- Produces: `fn extract_user_dbs(merged_tar: &std::path::Path) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>)>` (module-private).

- [ ] **Step 1: Write the failing test**

Add to `mod tests` (a tar with `./etc/passwd` absolute-ish + last-wins, and no group):

```rust
    #[test]
    fn extract_user_dbs_reads_passwd_handles_paths_and_last_wins() {
        use std::io::Write as _;
        let tmp = tempfile::tempdir().unwrap();
        let tar_path = tmp.path().join("merged.tar");
        {
            let f = fs::File::create(&tar_path).unwrap();
            let mut b = tar::Builder::new(f);
            let add = |b: &mut tar::Builder<fs::File>, path: &str, data: &[u8]| {
                let mut h = tar::Header::new_gnu();
                h.set_size(data.len() as u64);
                h.set_entry_type(tar::EntryType::Regular);
                h.set_mode(0o644);
                h.set_cksum();
                b.append_data(&mut h, path, data).unwrap();
            };
            add(&mut b, "etc/passwd", b"root:x:0:0::/root:/bin/sh\n");
            // a later, absolute-prefixed entry for the same logical path wins
            add(&mut b, "/etc/passwd", b"node:x:1000:1000::/home/node:/bin/sh\n");
            b.finish().unwrap();
        }
        let (passwd, group) = extract_user_dbs(&tar_path).unwrap();
        let passwd = String::from_utf8(passwd.expect("passwd present")).unwrap();
        assert!(passwd.contains("node:x:1000"), "last-wins entry must win: {passwd}");
        assert!(group.is_none(), "no /etc/group entry -> None");
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p izba-core --lib image::tests::extract_user_dbs 2>&1 | tail -20`
Expected: FAIL — `extract_user_dbs` not found.

- [ ] **Step 3: Implement the extractor + capture in `publish_image`**

Add the helper near the top of `mod.rs` (after the `use` block):

```rust
/// Pull the raw bytes of `etc/passwd` and `etc/group` out of a flattened image
/// tar. Matches the canonical paths regardless of a leading `/` or `./`;
/// last entry wins (the flattened tar is lowest-layer-first, so a higher layer's
/// passwd appears later and overrides). Only regular-file entries are read.
fn extract_user_dbs(
    merged_tar: &std::path::Path,
) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>)> {
    let f = fs::File::open(merged_tar)
        .with_context(|| format!("failed to open {}", merged_tar.display()))?;
    let mut ar = tar::Archive::new(f);
    let mut passwd = None;
    let mut group = None;
    for entry in ar.entries().context("reading merged tar")? {
        let mut entry = entry.context("reading merged tar entry")?;
        if entry.header().entry_type() != tar::EntryType::Regular {
            continue;
        }
        let path = entry.path().context("entry path")?;
        let norm = path
            .to_string_lossy()
            .trim_start_matches("./")
            .trim_start_matches('/')
            .to_string();
        let slot = match norm.as_str() {
            "etc/passwd" => &mut passwd,
            "etc/group" => &mut group,
            _ => continue,
        };
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut entry, &mut buf).context("reading user db entry")?;
        *slot = Some(buf); // last-wins
    }
    Ok((passwd, group))
}
```

Then in `publish_image`'s build closure, capture before removing `merged.tar`. Change the closure body (lines ~39-48) to:

```rust
    store.publish(digest, |staging| {
        let merged_tar = staging.join("merged.tar");
        let out = fs::File::create(&merged_tar)
            .with_context(|| format!("failed to create {}", merged_tar.display()))?;
        flatten_layers(layers, std::io::BufWriter::new(out))
            .with_context(|| format!("failed to flatten layers of {image_ref}"))?;
        erofs::build_erofs(&merged_tar, &staging.join("rootfs.erofs"))?;
        // Capture the image's user databases for host-side symbolic-USER
        // resolution (issue #96) before the merged tar is discarded.
        let (passwd, group) = extract_user_dbs(&merged_tar)?;
        if let Some(p) = &passwd {
            fs::write(staging.join("passwd"), p)?;
        }
        if let Some(g) = &group {
            fs::write(staging.join("group"), g)?;
        }
        fs::remove_file(&merged_tar)?;
        fs::write(staging.join("ref.txt"), image_ref)?;
        fs::write(staging.join("config.json"), config_json)?;
        Ok(())
    })?;
```

(We write directly into `staging` here — the dir is renamed into place atomically by `publish`, so this matches how `config.json`/`ref.txt` are written. `persist_user_dbs` from Task 3 is the post-publish/self-heal path used by callers that operate on an already-published digest; it is exercised by Task 3's tests and available for future self-heal.)

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p izba-core --lib image::tests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/image/mod.rs
git commit -m "feat(core): capture image passwd/group during flatten"
```

---

### Task 5: wire the image `UserDb` into `write_oci_bundle`

**Files:**
- Modify: `crates/izba-core/src/sandbox.rs` (`write_oci_bundle` ~538-562; call site ~714-724)
- Test: existing `sandbox.rs` tests + the workspace build.

**Interfaces:**
- Consumes: `ImageStore::load_user_dbs` (Task 3), `UserDb::from_files` + `resolve_process_user` (Tasks 1-2).
- Produces: `write_oci_bundle` gains a `user_db: &crate::image::runtime_config::UserDb` parameter.

- [ ] **Step 1: Update the call site and signature**

In `write_oci_bundle` signature (line ~538), add a parameter:

```rust
fn write_oci_bundle(
    oci_dir: &Path,
    name: &str,
    image_config: Option<&oci_client::config::Config>,
    user_db: &crate::image::runtime_config::UserDb,
    ca_present: bool,
    workspace: &Path,
    privileged: bool,
) -> anyhow::Result<()> {
```

Change the resolve call (line ~557) to pass the db:

```rust
    let ((uid, gid), user_warn) = crate::image::runtime_config::resolve_process_user(
        image_config.and_then(|c| c.user.as_deref()),
        user_db,
    );
```

At the call site (line ~714), load the dbs and pass them:

```rust
    let image_cfg_file = ImageStore::new(paths).load_config(&config.image_digest)?;
    let image_config = image_cfg_file.as_ref().and_then(|f| f.config.as_ref());
    let (passwd, group) = ImageStore::new(paths).load_user_dbs(&config.image_digest)?;
    let user_db =
        crate::image::runtime_config::UserDb::from_files(passwd.as_deref(), group.as_deref());
    write_oci_bundle(
        &oci_dir,
        name,
        image_config,
        &user_db,
        trust_dir.join("ca.pem").exists(),
        &config.workspace,
        config.builder,
    )
    .with_context(|| format!("writing oci/config.json for sandbox '{name}'"))?;
```

Also update any other `write_oci_bundle(` call inside `sandbox.rs` tests (search for it) to pass `&UserDb::default()`.

- [ ] **Step 2: Build + run the workspace tests**

Run: `cargo test -p izba-core --lib sandbox 2>&1 | tail -25`
Expected: PASS (compile clean; existing bundle tests still green — default empty db ⇒ unchanged root/numeric behaviour).

- [ ] **Step 3: Add a sandbox-level test proving symbolic resolution flows through**

If `sandbox.rs` tests construct a bundle (search for a test reading the written `config.json`), add one that writes passwd into the store and asserts the resolved uid lands in `process.user`. If the existing test harness makes this awkward, this assertion is already covered end-to-end by Task 6; in that case skip and note it. Prefer adding when cheap:

```rust
    #[test]
    fn write_oci_bundle_resolves_symbolic_user_from_db() {
        // (Mirror the existing bundle test's setup; pass a UserDb with `node`.)
        // Assert spec.process().user().uid() == 1000 for an image whose User is "node".
    }
```

- [ ] **Step 4: Full workspace gates**

Run:
```bash
cargo test --workspace 2>&1 | tail -15
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -15
cargo fmt --check
```
Expected: all green.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/sandbox.rs
git commit -m "feat(core): resolve image symbolic USER host-side at sandbox start (#96)"
```

---

### Task 6: real-VM integration test — symbolic `USER` round-trip

**Files:**
- Modify: `crates/izba-core/tests/integration.rs` (extend the Option-A userns round-trip harness, ~line 686+)

**Interfaces:**
- Consumes: the full pipeline (Tasks 1-5).

- [ ] **Step 1: Pick the fixture image**

Reuse the integration suite's existing image-build/pull pattern (read how the current userns tests obtain their image around lines 150 & 686). Use an image that declares a **named** `USER` whose passwd entry is known. Preferred: build a tiny local image in the test (Dockerfile `FROM alpine` + `RUN adduser -D -u 1234 appuser` + `USER appuser`) via the existing build path; fallback to a pinned public image with a known symbolic USER + uid. Document the chosen uid inline.

- [ ] **Step 2: Write the test (gated like its neighbours)**

```rust
/// Symbolic image USER (`USER appuser`, uid 1234 in the image's passwd) is
/// resolved host-side: the workload runs as 1234 and owns /workspace.
#[test]
#[cfg(unix)]
fn userns_resolves_symbolic_image_user() {
    // mirror the existing Option-A round-trip setup; build/pull the appuser image,
    // start the sandbox, then:
    //   - exec `id -u` -> "1234"
    //   - exec `stat -c %u /workspace` -> "1234"
    // (Use the shared assertions helper the neighbouring tests use.)
}
```

- [ ] **Step 3: Run locally (KVM, sandbox disabled)**

Run: `IZBA_INTEGRATION=1 cargo test -p izba-core --test integration userns_resolves_symbolic_image_user -- --test-threads=1 --nocapture`
Expected: PASS. (Per CLAUDE.md, run unsandboxed — `/dev/kvm` works here.)

- [ ] **Step 4: Commit**

```bash
git add crates/izba-core/tests/integration.rs
git commit -m "test(core): e2e symbolic image USER resolves to its numeric uid (#96)"
```

---

## Self-Review notes

- **Spec coverage:** capture (Task 4) ✓, store (Task 3) ✓, resolver (Tasks 1-2) ✓, wire-up (Task 5) ✓, e2e (Task 6) ✓, legacy-cache graceful fallback (Tasks 2/3 — empty db ⇒ loud root) ✓, numeric-unchanged (Task 1/2 tests) ✓.
- **Loud-fallback message** changed wording; the only assertion on it is `contains("ghost")`/`contains(USER)` — still holds.
- **Windows cross-gate:** all changes are in `izba-core` pure logic + store/flatten (already cross-compiled); no platform-specific APIs added. Run the two `x86_64-pc-windows-gnu` gates from CLAUDE.md before the final push.
- **App gate:** no `izba-core` *public wire types* changed (only an internal fn signature + new pure helpers), so the Tauri app build is unaffected; still run it if the final review flags any `DaemonRequest`/proto touch (none here).
