# Peer-Rejected Client Diagnosis (#231) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A client that izbad refuses for running as the wrong uid gets an error naming both uids and the daemon log, and no longer forks a stray `izba daemon run`.

**Architecture:** izbad's accept loop (`server::accept_and_dispatch`, F-09) closes a foreign-uid connection before reading a frame, so the client's hello exchange dies with EOF / `ECONNRESET` / `EPIPE`. Today `is_daemon_gone` reads that as "the daemon died" and `connect_with` spawns a new daemon. The fix adds a client-side diagnosis that fires only when BOTH hold: the handshake was cut off, and the control socket file is verifiably owned by a different uid than this process. That turns into a typed `PeerRejected` error which `is_daemon_gone` does not match, so it propagates instead of reaching the spawn path. With the same uid on both sides the signal stays ambiguous and today's behaviour is untouched.

**Tech Stack:** Rust (`izba-core` daemon client, `izba-cli` clap help), `anyhow`, `std::os::unix::fs::MetadataExt`, existing `peercred` module.

**Spec:** GitHub issue [#231](https://github.com/Lupus/izba/issues/231) (body + the 2026-08-19 comment). There is no separate design doc; the issue's Acceptance Criteria are the contract.

## Global Constraints

- No `DAEMON_PROTO_VERSION` bump and no wire/frame change of any kind.
- No daemon-side change to rejection semantics or to the daemon-log line in `peer_denial_log`.
- The diagnosis may only state measured facts: it must never claim a uid mismatch that was not read from the socket file's owner and this process's euid.
- A handshake cut off between a daemon and a client of the SAME uid keeps today's exact behaviour (respawn attempt, `reading hello reply: …` text).
- Unit tests never bind a unix listener unconditionally: use `UdsStream::pair()` or plain files, and any test that truly needs a listener runtime-skips through the existing `bind_denied(&paths)` helper.
- `cargo clippy --target x86_64-pc-windows-gnu --all-targets … -D warnings` must stay clean: every test helper used only by `#[cfg(unix)]`/`#[cfg(target_os = "linux")]` tests carries the same `cfg`.
- Conventional commits; each commit body ends with `Refs #231`. Stage files explicitly by path — never `git add -A`.
- Toolchain: `cd /home/kolkhovskiy/git/izba && source .cargo-env && cd -` in the same shell invocation as every `cargo` command (the env file is `$PWD`-relative and lives only in the main checkout). Export `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0` (disk is tight).

## Review Focus

- **Same-uid cut-off handshake** (daemon idle-exits mid-accept): must still respawn once and report `reading hello reply`, never a uid message. Pinned by `connect_with_still_respawns_on_a_dropped_handshake_from_its_own_uid` (Task 1).
- **`EPIPE` on the hello WRITE** (izbad closed before the client wrote): must be diagnosed like the EOF/reset on the read. Pinned by `a_closed_peer_fails_the_handshake_as_dropped` + the `BrokenPipe` row of `handshake_dropped_detection` (Task 1).
- **A handshake that TIMES OUT against a foreign-uid socket** (wedged daemon, not a refusal): must not be reported as a refusal. Pinned by `peer_rejection_is_none_when_the_handshake_was_not_cut_off` (Task 1).
- **`izba daemon status` / `stop` as the wrong uid** (strict `connect_existing`, never spawns): must show the same diagnosis instead of the opaque text. Pinned by the `connect_existing_as` assertion inside `connect_with_does_not_spawn_when_the_daemon_refuses_this_uid` (Task 1) and the `daemon status` step of the e2e (Task 4).
- **A stray spawn in the ambiguous case must stay harmless**: it loses the flock before it can unlink the socket or truncate the owner's log. Pinned by the three invariant tests in Task 2.

---

### Task 1: Diagnose a refused client and skip the spawn

**Files:**
- Modify: `crates/izba-core/src/daemon/client.rs` (imports at top; `connect_existing` at :36; `connect_existing_tolerant` at :56; `connect`/`connect_spawning_izba`/`connect_with` at :66-117; new items after `is_daemon_gone` at :314; tests module at :407)

**Interfaces:**
- Consumes: `peercred::owner_uid() -> Option<u32>`, `peercred::enforcement_mode() -> PeerAuth`, `Paths::{daemon_socket, daemon_log, daemon_lock, daemon_dir}`.
- Produces (all private to `client.rs`): `struct PeerRejected { socket: PathBuf, daemon_log: PathBuf, daemon_uid: u32, client_uid: u32 }`; `fn peer_rejection(paths: &Paths, e: &anyhow::Error, client_uid: Option<u32>) -> Option<PeerRejected>`; `DaemonClient::connect_existing_as(paths: &Paths, client_uid: Option<u32>)`; `connect_with(paths, spawner, my_version, client_uid: Option<u32>)`; test helper `hold_daemon_lock(paths: &Paths) -> std::fs::File` (Task 2 uses it).

- [ ] **Step 1: Write the failing unit tests (no listener needed)**

Add inside `mod tests` in `crates/izba-core/src/daemon/client.rs`:

```rust
    /// This process's uid — the uid that owns every file these tests create.
    #[cfg(unix)]
    fn my_uid() -> u32 {
        crate::daemon::peercred::owner_uid().expect("unix has a uid")
    }

    /// Take the daemon flock the way a live izbad does, so the client's
    /// `clear_stale_socket` sees "a daemon is alive". (`cfg(unix)` only
    /// because its users in this task are; Task 2 adds platform-neutral
    /// users and drops the attribute.)
    #[cfg(unix)]
    fn hold_daemon_lock(paths: &crate::paths::Paths) -> std::fs::File {
        std::fs::create_dir_all(paths.daemon_dir()).unwrap();
        let f = std::fs::File::options()
            .create(true)
            .truncate(false)
            .write(true)
            .open(paths.daemon_lock())
            .unwrap();
        f.try_lock().expect("the test holds the daemon lock");
        f
    }

    /// An error shaped like the real hello-exchange failure of that io kind.
    fn hello_io_error(kind: std::io::ErrorKind) -> anyhow::Error {
        use anyhow::Context as _;
        Err::<(), _>(izba_proto::FrameError::Io(std::io::Error::from(kind)))
            .context("reading hello reply")
            .unwrap_err()
    }

    fn hello_eof() -> anyhow::Error {
        use anyhow::Context as _;
        Err::<(), _>(izba_proto::FrameError::Eof)
            .context("reading hello reply")
            .unwrap_err()
    }

    #[test]
    fn uid_mismatch_needs_two_known_and_different_uids() {
        assert_eq!(uid_mismatch(Some(1000), Some(0)), Some((1000, 0)));
        assert_eq!(uid_mismatch(Some(0), Some(1000)), Some((0, 1000)));
        assert_eq!(uid_mismatch(Some(1000), Some(1000)), None);
        assert_eq!(uid_mismatch(None, Some(0)), None);
        assert_eq!(uid_mismatch(Some(1000), None), None);
    }

    /// Every way izbad's close-without-reading can surface on the client —
    /// and the two that are NOT a cut-off connection.
    #[test]
    fn handshake_dropped_detection() {
        use std::io::ErrorKind;
        assert!(handshake_dropped(&hello_eof()));
        assert!(handshake_dropped(&hello_io_error(ErrorKind::UnexpectedEof)));
        assert!(handshake_dropped(&hello_io_error(ErrorKind::ConnectionReset)));
        assert!(handshake_dropped(&hello_io_error(ErrorKind::BrokenPipe)));
        // A raw io error (no FrameError wrapper) counts too.
        assert!(handshake_dropped(&anyhow::Error::new(std::io::Error::from(
            ErrorKind::ConnectionReset
        ))));
        // A wedged daemon times out; that is not a refusal.
        assert!(!handshake_dropped(&hello_io_error(ErrorKind::TimedOut)));
        assert!(!handshake_dropped(&hello_io_error(ErrorKind::PermissionDenied)));
        assert!(!handshake_dropped(&anyhow::anyhow!("unexpected hello reply")));
    }

    /// The real signal, not a synthesized one: a peer that is already closed
    /// fails the client's hello exchange in a way `handshake_dropped` matches.
    /// Unix only: the refusal exists only where izbad enforces peer uids, and
    /// WinSock reports a closed peer with different error kinds.
    #[cfg(unix)]
    #[test]
    fn a_closed_peer_fails_the_handshake_as_dropped() {
        let (client, server) = UdsStream::pair().unwrap();
        drop(server);
        let err = match DaemonClient::handshake(client, "v") {
            Ok(_) => panic!("a closed peer cannot complete the hello"),
            Err(e) => e,
        };
        assert!(handshake_dropped(&err), "{err:#}");
    }

    #[cfg(unix)]
    #[test]
    fn socket_owner_uid_reads_the_file_owner() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("izbad.sock");
        assert_eq!(socket_owner_uid(&f), None, "absent file has no owner");
        std::fs::write(&f, b"").unwrap();
        assert_eq!(socket_owner_uid(&f), Some(my_uid()));
    }

    /// A data root holding a plain file where the control socket lives: the
    /// diagnosis only stats the path, so no listener is needed.
    #[cfg(unix)]
    fn paths_with_socket_file() -> (tempfile::TempDir, crate::paths::Paths) {
        let dir = tempfile::tempdir().unwrap();
        let paths = crate::paths::Paths::with_root(dir.path().join("izba"));
        std::fs::create_dir_all(paths.daemon_dir()).unwrap();
        std::fs::write(paths.daemon_socket(), b"").unwrap();
        (dir, paths)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn peer_rejection_names_both_uids_when_the_socket_belongs_to_someone_else() {
        let (_dir, paths) = paths_with_socket_file();
        let stranger = my_uid() + 1;
        assert_eq!(
            peer_rejection(&paths, &hello_eof(), Some(stranger)),
            Some(PeerRejected {
                socket: paths.daemon_socket(),
                daemon_log: paths.daemon_log(),
                daemon_uid: my_uid(),
                client_uid: stranger,
            })
        );
    }

    /// Same uid on both sides: the cut-off is the ambiguous idle-exit race,
    /// which must keep today's behaviour — never a uid message.
    #[cfg(target_os = "linux")]
    #[test]
    fn peer_rejection_is_none_for_the_sockets_own_uid() {
        let (_dir, paths) = paths_with_socket_file();
        assert_eq!(peer_rejection(&paths, &hello_eof(), Some(my_uid())), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn peer_rejection_is_none_when_the_handshake_was_not_cut_off() {
        let (_dir, paths) = paths_with_socket_file();
        let timed_out = hello_io_error(std::io::ErrorKind::TimedOut);
        assert_eq!(peer_rejection(&paths, &timed_out, Some(my_uid() + 1)), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn peer_rejection_is_none_without_a_socket_or_a_client_uid() {
        let (_dir, paths) = paths_with_socket_file();
        assert_eq!(peer_rejection(&paths, &hello_eof(), None), None);
        std::fs::remove_file(paths.daemon_socket()).unwrap();
        assert_eq!(peer_rejection(&paths, &hello_eof(), Some(my_uid() + 1)), None);
    }

    #[test]
    fn peer_rejected_message_names_both_uids_the_socket_and_the_log() {
        let rejected = PeerRejected {
            socket: "/data/daemon/izbad.sock".into(),
            daemon_log: "/data/daemon/daemon.log".into(),
            daemon_uid: 1000,
            client_uid: 0,
        };
        let msg = format!("{:#}", anyhow::Error::new(rejected));
        assert!(msg.contains("belongs to uid 1000"), "{msg}");
        assert!(msg.contains("running as uid 0"), "{msg}");
        assert!(msg.contains("/data/daemon/izbad.sock"), "{msg}");
        assert!(msg.contains("/data/daemon/daemon.log"), "{msg}");
        assert!(!msg.contains("reading hello reply"), "{msg}");
    }

    /// The whole point: a refusal must not look like a dead daemon, or
    /// `connect_with` would spawn a new one.
    #[test]
    fn peer_rejected_is_not_daemon_gone() {
        let rejected = anyhow::Error::new(PeerRejected {
            socket: "/s".into(),
            daemon_log: "/l".into(),
            daemon_uid: 1000,
            client_uid: 0,
        });
        assert!(!is_daemon_gone(&rejected));
    }
```

- [ ] **Step 2: Run them — they must fail to compile**

Run: `cargo test -p izba-core --lib daemon::client 2>&1 | tail -20`
Expected: compile errors — `uid_mismatch`, `handshake_dropped`, `socket_owner_uid`, `peer_rejection`, `PeerRejected` not found.

- [ ] **Step 3: Implement the diagnosis**

At the top of `client.rs` add to the imports:

```rust
use std::path::{Path, PathBuf};

use crate::daemon::peercred;
```

After `is_daemon_gone` add:

```rust
/// izbad will not serve this client: the hello exchange was cut off AND the
/// control socket belongs to another uid (#231). izbad's accept-time peer
/// check (F-09, `server::accept_and_dispatch`) refuses every uid but its
/// owner's by closing the connection before it reads a frame, which the
/// client can only see as a dead connection. This carries measured facts —
/// the socket file's owner and this process's euid — so the message never
/// asserts a mismatch that may not exist.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PeerRejected {
    socket: PathBuf,
    daemon_log: PathBuf,
    daemon_uid: u32,
    client_uid: u32,
}

impl std::fmt::Display for PeerRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "izbad closed the connection without answering: its control socket {} belongs to \
             uid {}, but this izba is running as uid {}. izbad serves only the user who \
             started it — rerun izba as that user (for example, without sudo). Each refused \
             connection is logged in {}",
            self.socket.display(),
            self.daemon_uid,
            self.client_uid,
            self.daemon_log.display()
        )
    }
}

impl std::error::Error for PeerRejected {}

/// `(daemon uid, client uid)` when both are known and differ.
fn uid_mismatch(socket_owner: Option<u32>, client: Option<u32>) -> Option<(u32, u32)> {
    match (socket_owner, client) {
        (Some(daemon), Some(client)) if daemon != client => Some((daemon, client)),
        _ => None,
    }
}

/// The uid that owns the control socket file. izbad binds it itself
/// (`transport::bind_socket`), so on unix that is the daemon's own uid.
/// `None` where there is no uid concept or the file cannot be stat'ed.
fn socket_owner_uid(sock: &Path) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(sock).ok().map(|m| m.uid())
    }
    #[cfg(not(unix))]
    {
        let _ = sock;
        None
    }
}

/// Was the hello exchange cut off by the peer closing the connection?
/// izbad's refusal closes without reading, which reaches the client as a
/// clean EOF, `ECONNRESET` (our hello was still unread), or `EPIPE` on the
/// hello write (it closed before we wrote). A timeout is NOT a cut-off: a
/// refusing daemon closes at once, a wedged one does not.
fn handshake_dropped(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        let io = match c.downcast_ref::<izba_proto::FrameError>() {
            Some(izba_proto::FrameError::Eof) => return true,
            Some(izba_proto::FrameError::Io(io)) => Some(io),
            Some(_) => None,
            None => c.downcast_ref::<std::io::Error>(),
        };
        io.is_some_and(|io| {
            matches!(
                io.kind(),
                std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe
            )
        })
    })
}

/// Diagnose a failed hello exchange as izbad's peer-uid refusal, or `None`
/// when the evidence does not support that. Gated on
/// `peercred::enforcement_mode()` — the same predicate the daemon's accept
/// loop uses — so the client never reports a refusal on a platform whose
/// daemon cannot perform one.
fn peer_rejection(
    paths: &Paths,
    e: &anyhow::Error,
    client_uid: Option<u32>,
) -> Option<PeerRejected> {
    if peercred::enforcement_mode() != peercred::PeerAuth::Enforced || !handshake_dropped(e) {
        return None;
    }
    let socket = paths.daemon_socket();
    let (daemon_uid, client_uid) = uid_mismatch(socket_owner_uid(&socket), client_uid)?;
    Some(PeerRejected {
        socket,
        daemon_log: paths.daemon_log(),
        daemon_uid,
        client_uid,
    })
}
```

- [ ] **Step 4: Run the unit tests — they must pass**

Run: `cargo test -p izba-core --lib daemon::client 2>&1 | tail -20`
Expected: all `daemon::client` tests pass (dead-code warnings for the not-yet-wired functions are fine at this step).

- [ ] **Step 5: Write the failing connect-path tests (real listener, runtime-skip)**

Add inside `mod tests`:

```rust
    /// An izbad stand-in that accepts and closes every connection without
    /// answering. It waits for the hello first, so the client's failure is
    /// deterministically a clean EOF on its reply read (the real izbad closes
    /// without reading, which can also surface as ECONNRESET or EPIPE — the
    /// classifier's unit tests cover those).
    #[cfg(unix)]
    fn serve_dropping_daemon(paths: &crate::paths::Paths) -> anyhow::Result<()> {
        let listener = crate::daemon::transport::bind_socket(paths)?;
        std::thread::spawn(move || loop {
            let Ok((mut s, _peer)) = listener.accept() else {
                return;
            };
            let _ = read_frame::<_, DaemonHello>(&mut s);
        });
        Ok(())
    }

    /// #231: a client the daemon refuses for its uid must NOT spawn a daemon,
    /// and must get the uid diagnosis — through both the spawning and the
    /// strict (`daemon status`/`stop`) entry points.
    #[cfg(target_os = "linux")]
    #[test]
    fn connect_with_does_not_spawn_when_the_daemon_refuses_this_uid() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let dir = tempfile::tempdir().unwrap();
        let paths = crate::paths::Paths::with_root(dir.path().join("izba"));
        if bind_denied(&paths) {
            return;
        }
        let _lock = hold_daemon_lock(&paths);
        serve_dropping_daemon(&paths).unwrap();
        let stranger = Some(my_uid() + 1);

        let spawned = AtomicUsize::new(0);
        let err = match DaemonClient::connect_with(
            &paths,
            &|_p: &crate::paths::Paths| {
                spawned.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            "v",
            stranger,
        ) {
            Ok(_) => panic!("a refused client cannot connect"),
            Err(e) => e,
        };
        assert_eq!(spawned.load(Ordering::SeqCst), 0, "no stray daemon: {err:#}");
        let rejected = err.downcast_ref::<PeerRejected>().expect("uid diagnosis");
        assert_eq!(rejected.daemon_uid, my_uid());
        assert_eq!(Some(rejected.client_uid), stranger);

        let strict = match DaemonClient::connect_existing_as(&paths, stranger) {
            Ok(_) => panic!("a refused client cannot connect"),
            Err(e) => e,
        };
        assert!(strict.downcast_ref::<PeerRejected>().is_some(), "{strict:#}");
    }

    /// The ambiguous case keeps today's behaviour: the SAME uid seeing a
    /// cut-off handshake is the idle-exit race, so the client respawns once
    /// and, when that does not help, reports the plain handshake error.
    #[cfg(unix)]
    #[test]
    fn connect_with_still_respawns_on_a_dropped_handshake_from_its_own_uid() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let dir = tempfile::tempdir().unwrap();
        let paths = crate::paths::Paths::with_root(dir.path().join("izba"));
        if bind_denied(&paths) {
            return;
        }
        // A live daemon holds the flock, so the client's pre-spawn cleanup
        // leaves the socket alone and the retry reaches the same listener.
        let _lock = hold_daemon_lock(&paths);
        serve_dropping_daemon(&paths).unwrap();

        let spawned = AtomicUsize::new(0);
        let err = match DaemonClient::connect_with(
            &paths,
            &|_p: &crate::paths::Paths| {
                spawned.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            "v",
            Some(my_uid()),
        ) {
            Ok(_) => panic!("the stand-in never answers the hello"),
            Err(e) => e,
        };
        assert_eq!(spawned.load(Ordering::SeqCst), 1, "respawn attempted once");
        assert!(err.downcast_ref::<PeerRejected>().is_none(), "{err:#}");
        assert!(format!("{err:#}").contains("reading hello reply"), "{err:#}");
    }

    /// The public strict entry point: absent daemon is `None`, a serving one
    /// is `Some` (it now delegates, so pin the wrapper itself).
    #[test]
    fn connect_existing_reports_absence_and_finds_a_serving_daemon() {
        let dir = tempfile::tempdir().unwrap();
        let paths = crate::paths::Paths::with_root(dir.path().join("izba"));
        assert!(DaemonClient::connect_existing(&paths).unwrap().is_none());
        if bind_denied(&paths) {
            return;
        }
        serve_fake_daemon(&paths, "v1", DAEMON_PROTO_VERSION).unwrap();
        let client = DaemonClient::connect_existing(&paths).unwrap().expect("daemon found");
        assert_eq!(client.server_version, "v1");
    }
```

Also update the three existing `connect_with` call sites in the tests (`connect_with_spawns_when_absent`, `connect_with_restarts_on_proto_mismatch`, `connect_with_keeps_daemon_on_build_only_diff`) to pass a fourth argument: `crate::daemon::peercred::owner_uid()`.

- [ ] **Step 6: Run them — they must fail to compile**

Run: `cargo test -p izba-core --lib daemon::client 2>&1 | tail -20`
Expected: compile errors — `connect_existing_as` not found; `connect_with` takes 3 arguments but 4 were supplied.

- [ ] **Step 7: Wire the diagnosis into the connect path**

Replace `connect_existing`, `connect_existing_tolerant`, `connect`, `connect_spawning_izba` and the head of `connect_with` with:

```rust
    /// Connect to a running daemon. `Ok(None)` when there is none (missing
    /// socket or nothing accepting). Never auto-starts.
    pub fn connect_existing(paths: &Paths) -> anyhow::Result<Option<DaemonClient>> {
        Self::connect_existing_as(paths, peercred::owner_uid())
    }

    /// [`Self::connect_existing`] with this process's uid injected, so the
    /// refused-client diagnosis (#231) is testable without a second uid.
    fn connect_existing_as(
        paths: &Paths,
        client_uid: Option<u32>,
    ) -> anyhow::Result<Option<DaemonClient>> {
        // Check the socket file first: it is the cross-platform "is there a
        // daemon" signal (the daemon unlinks it on exit), and it sidesteps
        // WinSock's unhelpful errno mapping for dead AF_UNIX paths.
        if !paths.daemon_socket().exists() {
            return Ok(None);
        }
        match transport::connect_socket(paths) {
            Ok(s) => match Self::handshake(s, &transport::daemon_version()) {
                Ok(client) => Ok(Some(client)),
                // A daemon that refuses our uid closes without answering.
                // Say so, instead of the bare "reading hello reply" — and as
                // a typed error `is_daemon_gone` does not match, so
                // `connect_with` cannot mistake it for a dead daemon and
                // spawn another one.
                Err(e) => Err(match peer_rejection(paths, &e, client_uid) {
                    Some(rejected) => anyhow::Error::new(rejected),
                    None => e,
                }),
            },
            Err(e) if connect_says_no_daemon(&e) => Ok(None),
            Err(e) => Err(e).context("connecting to the izbad socket"),
        }
    }

    /// Like [`Self::connect_existing`], but a handshake that dies mid-flight
    /// (EOF / reset / timeout) also counts as "no daemon": a daemon caught
    /// mid-idle-exit accepts from the backlog then exits before serving the
    /// hello. The spec contract is auto-restart — worst case one retry — so
    /// `connect_with` treats that as absent and takes the spawn path.
    /// `connect_existing` itself stays strict (status/stop must not spawn).
    /// A peer-uid refusal is NOT "no daemon": it arrives as `PeerRejected`,
    /// which `is_daemon_gone` does not match, and propagates (#231).
    fn connect_existing_tolerant(
        paths: &Paths,
        client_uid: Option<u32>,
    ) -> anyhow::Result<Option<DaemonClient>> {
        match Self::connect_existing_as(paths, client_uid) {
            Ok(c) => Ok(c),
            Err(e) if is_daemon_gone(&e) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Daemon-first connect: auto-start when absent, auto-upgrade (shutdown +
    /// respawn) on wire-protocol mismatch.
    pub fn connect(paths: &Paths) -> anyhow::Result<DaemonClient> {
        Self::connect_with(
            paths,
            &spawn_daemon,
            &transport::daemon_version(),
            peercred::owner_uid(),
        )
    }
```

`connect_spawning_izba` keeps its doc comment and becomes:

```rust
    pub fn connect_spawning_izba(paths: &Paths) -> anyhow::Result<DaemonClient> {
        Self::connect_with(
            paths,
            &spawn_sibling_izba,
            &transport::daemon_version(),
            peercred::owner_uid(),
        )
    }
```

`connect_with` gains the parameter and passes it on — only these lines change:

```rust
    /// Seam for tests: injectable spawner + client version + client uid.
    fn connect_with(
        paths: &Paths,
        spawner: &dyn Fn(&Paths) -> anyhow::Result<()>,
        my_version: &str,
        client_uid: Option<u32>,
    ) -> anyhow::Result<DaemonClient> {
        for attempt in 0..2 {
            let client = match Self::connect_existing_tolerant(paths, client_uid)? {
```

- [ ] **Step 8: Run the whole client module — everything passes**

Run: `cargo test -p izba-core --lib daemon::client 2>&1 | tail -30`
Expected: PASS. In a sandbox that denies `bind`, the three listener tests print `SKIP: bind denied in this environment` — that is acceptable locally, but then ALSO run the same command with the Bash sandbox disabled so the listener tests genuinely execute, and report which mode produced the result.

- [ ] **Step 9: Prove the no-spawn test bites**

Temporarily change `Err(match peer_rejection(paths, &e, client_uid) { … })` to `Err(e)`, re-run `cargo test -p izba-core --lib daemon::client::tests::connect_with_does_not_spawn` (unsandboxed, so it does not skip) and confirm it FAILS with `no stray daemon` / spawned = 1. Restore the code and re-run to green. Record both outputs in your report.

- [ ] **Step 10: Lint both targets**

Run:
```bash
cargo fmt --check
cargo clippy -p izba-core --all-targets -- -D warnings
cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-core -- -D warnings
```
Expected: clean. (If the Windows target is not installed in this checkout, say so in the report rather than skipping silently.)

- [ ] **Step 11: Commit**

```bash
git add crates/izba-core/src/daemon/client.rs
git commit -m "fix(core): diagnose a peer-uid refusal instead of spawning a stray daemon

izbad refuses a connection from any uid but its owner's by closing it
before reading a frame. The client read that as a dead daemon, forked a
new 'izba daemon run' that lost the flock at once, and reported a bare
'reading hello reply' error.

The client now recognises the refusal when the hello exchange is cut off
AND the control socket file is owned by another uid, reports both uids
and the daemon log, and returns a typed error the spawn path does not
treat as a dead daemon. A cut-off between a daemon and a client of the
same uid stays ambiguous and keeps the respawn behaviour.

Refs #231"
```

---

### Task 2: Pin the invariants that keep a stray spawn harmless

A stray `izba daemon run` can still happen in the ambiguous same-uid case. Two orderings make it harmless, and nothing pins them today.

**Files:**
- Modify: `crates/izba-core/src/daemon/client.rs` (doc comment on `clear_stale_socket`; two tests in `mod tests`)
- Modify: `crates/izba-core/src/daemon/server.rs` (comment at the log truncation in `run_daemon_with`, ~:2308; one test in the tests module next to `run_daemon_with_actually_serves`, ~:6508)

**Interfaces:**
- Consumes: `hold_daemon_lock(paths: &Paths) -> std::fs::File` from Task 1 (client.rs tests); `test_paths()` and `test_deps()` already in server.rs tests.
- Produces: nothing other tasks use.

- [ ] **Step 1: Write the client-side invariant tests**

First remove the `#[cfg(unix)]` attribute (and the parenthetical in its doc comment) from the `hold_daemon_lock` test helper Task 1 added — the tests below use it on every platform.

Add inside `mod tests` in `client.rs`:

```rust
    /// #231 invariant: while a daemon holds the flock, a client's pre-spawn
    /// cleanup must not unlink the live daemon's socket.
    #[test]
    fn clear_stale_socket_spares_the_socket_while_a_daemon_holds_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        let paths = crate::paths::Paths::with_root(dir.path().join("izba"));
        let _lock = hold_daemon_lock(&paths);
        // A plain file stands in for the socket: the cleanup is an unlink.
        std::fs::write(paths.daemon_socket(), b"").unwrap();
        clear_stale_socket(&paths).unwrap();
        assert!(paths.daemon_socket().exists(), "live daemon's socket unlinked");
    }

    /// …and with no daemon alive, the leftover socket is cleared so a fresh
    /// daemon can bind.
    #[test]
    fn clear_stale_socket_unlinks_a_leftover_socket_when_no_daemon_holds_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        let paths = crate::paths::Paths::with_root(dir.path().join("izba"));
        std::fs::create_dir_all(paths.daemon_dir()).unwrap();
        std::fs::write(paths.daemon_socket(), b"").unwrap();
        clear_stale_socket(&paths).unwrap();
        assert!(!paths.daemon_socket().exists(), "stale socket left behind");
    }
```

- [ ] **Step 2: Write the daemon-side invariant test**

Add in the `server.rs` tests module, next to `run_daemon_with_actually_serves`:

```rust
    /// #231 invariant: a second `izba daemon run` (a client's stray spawn)
    /// must lose the flock BEFORE it can truncate the running daemon's log.
    /// No listener is bound: the refusal happens before `bind_socket`.
    #[test]
    fn run_daemon_with_loses_the_flock_before_it_can_truncate_the_owners_log() {
        let (_dir, paths) = test_paths();
        std::fs::create_dir_all(paths.daemon_dir()).unwrap();
        let held = File::options()
            .create(true)
            .truncate(false)
            .write(true)
            .open(paths.daemon_lock())
            .unwrap();
        held.try_lock().expect("the test holds the daemon lock");
        std::fs::write(paths.daemon_log(), "owner daemon line\n").unwrap();

        let err = run_daemon_with(&paths, test_deps()).unwrap_err();

        assert!(err.to_string().contains("daemon already running"), "{err:#}");
        assert_eq!(
            std::fs::read_to_string(paths.daemon_log()).unwrap(),
            "owner daemon line\n",
            "a daemon that lost the flock truncated the owner's log"
        );
    }
```

- [ ] **Step 3: Run them — they pass (they pin existing behaviour)**

Run: `cargo test -p izba-core --lib clear_stale_socket run_daemon_with_loses 2>&1 | tail -15` (run the two filters as two commands if cargo rejects two filters).
Expected: 3 tests pass.

- [ ] **Step 4: Prove each test bites**

These tests pin behaviour that already exists, so "watch it fail" means breaking the code on purpose, one at a time, and restoring it:
1. In `clear_stale_socket`, change `if f.try_lock().is_ok() {` to `if true {` → `clear_stale_socket_spares_the_socket_while_a_daemon_holds_the_lock` must FAIL. Restore.
2. In `clear_stale_socket`, change it to `if false {` → `clear_stale_socket_unlinks_a_leftover_socket_when_no_daemon_holds_the_lock` must FAIL. Restore.
3. In `run_daemon_with`, move `let _ = std::fs::File::create(paths.daemon_log());` to just above `match lock.try_lock() {` → `run_daemon_with_loses_the_flock_before_it_can_truncate_the_owners_log` must FAIL. Restore.

Confirm `git diff` shows no leftover sabotage, re-run to green, and record the three failing outputs in your report.

- [ ] **Step 5: Record the invariants at their sites**

Append to the doc comment on `clear_stale_socket` in `client.rs`:

```rust
///
/// INVARIANT (#231): the unlink is conditional on WINNING the flock. A client
/// that misreads a live daemon as gone reaches this function, and must not be
/// able to unlink that daemon's socket. Pinned by
/// `clear_stale_socket_spares_the_socket_while_a_daemon_holds_the_lock`.
```

In `run_daemon_with` in `server.rs`, extend the comment above `File::create(paths.daemon_log())`:

```rust
    // ORDERING IS LOAD-BEARING (#231): this must stay AFTER the flock above. A
    // client's stray `izba daemon run` loses the flock and bails before it
    // gets here, so it can never truncate the running daemon's log. Pinned by
    // `run_daemon_with_loses_the_flock_before_it_can_truncate_the_owners_log`.
```

- [ ] **Step 6: Lint and commit**

```bash
cargo fmt --check
cargo clippy -p izba-core --all-targets -- -D warnings
git add crates/izba-core/src/daemon/client.rs crates/izba-core/src/daemon/server.rs
git commit -m "test(core): pin the two orderings that keep a stray daemon spawn harmless

A client can still spawn a second 'izba daemon run' when a same-uid
handshake is cut off. That is harmless only because the client unlinks
the socket solely after winning the daemon flock, and the daemon
truncates its log solely after winning it. Neither ordering had a test.

Refs #231"
```

---

### Task 3: Make the daemon log discoverable

The daemon already logs an actionable line for each refusal, but no documented surface names the file (#231 comment, 2026-08-19).

**Files:**
- Modify: `crates/izba-cli/src/main.rs` (doc comment on the `Daemon` variant, ~:331; one test in the tests module near `run_policy_help_says_the_file_replaces_the_allow_list`, ~:1337)
- Modify: `README.md` (the "Daemon-first, daemonless soul" bullet, ~:38-42)

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: nothing other tasks use.

- [ ] **Step 1: Write the failing help test**

Add in the `main.rs` tests module:

```rust
    /// #231: a user whose command cannot reach the daemon needs to know
    /// where the daemon logs. `izba daemon --help` is the documented surface
    /// that names it.
    #[test]
    fn daemon_help_names_the_daemon_log() {
        use clap::CommandFactory;
        let mut cmd = Cli::command();
        let daemon = cmd.find_subcommand_mut("daemon").expect("daemon subcommand");
        let help = daemon.render_long_help().to_string();
        let flat = help.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(flat.contains("daemon/daemon.log"), "{flat}");
        assert!(flat.contains("only the user who started it"), "{flat}");
    }
```

- [ ] **Step 2: Run it — it must fail**

Run: `cargo test -p izba-cli --bin izba daemon_help_names_the_daemon_log 2>&1 | tail -15`
Expected: FAIL — the help text does not contain `daemon/daemon.log`.

- [ ] **Step 3: Extend the `Daemon` help**

In `main.rs`, replace the one-line doc comment on the `Daemon(DaemonCmd)` variant with:

```rust
    /// Manage the izba daemon (auto-started by other commands)
    ///
    /// The daemon logs to daemon/daemon.log under the izba data directory
    /// (~/.local/share/izba on Linux, %LOCALAPPDATA%\izba on Windows, or
    /// $IZBA_DATA_DIR); each daemon instance starts a fresh file. Look there
    /// when a command cannot reach the daemon. On Linux the daemon serves
    /// only the user who started it and logs every connection it refuses
    /// from another user — for example `sudo izba` against your own daemon.
```

Before committing, confirm the three data-dir spellings against `crates/izba-core/src/paths.rs` (`Paths::default`-style resolution near :14 and :213) and correct the text if the code says otherwise.

- [ ] **Step 4: Run it — it must pass, and the short help is unchanged**

Run: `cargo test -p izba-cli --bin izba daemon_help 2>&1 | tail -15`
Expected: PASS.
Run: `cargo run -q -p izba-cli -- --help | grep -n "daemon"`
Expected: still the single line `Manage the izba daemon (auto-started by other commands)`.

- [ ] **Step 5: README**

In `README.md`, extend the "Daemon-first, daemonless soul" bullet — after the sentence ending `…without harming running sandboxes.` add:

```markdown
  It logs to `~/.local/share/izba/daemon/daemon.log` (a fresh file per daemon
  instance). On Linux the daemon serves only the user who started it: a
  command run as another user — `sudo izba …` against your own daemon — is
  refused with an error naming both uids, and the daemon logs the refusal.
```

- [ ] **Step 6: Lint and commit**

```bash
cargo fmt --check
cargo clippy -p izba-cli --all-targets -- -D warnings
git add crates/izba-cli/src/main.rs README.md
git commit -m "docs(cli): name the daemon log in 'izba daemon --help' and the README

The daemon logs an actionable line for every connection it refuses from
another uid, but no documented surface said where that log lives.

Refs #231"
```

---

### Task 4: Prove it end to end with a real second uid

Tasks 1-3 inject the client uid. Only a real root client against a real user-owned izbad exercises `SO_PEERCRED`, the socket-owner stat and the CLI's rendering together.

**Files:**
- Modify: `crates/izba-cli/tests/daemon_e2e.rs` (one test + one helper, appended at the end of the file)

**Interfaces:**
- Consumes: existing helpers in that file — `want()`, `izba(data, envs, args)`, `assert_ok(o, what)`, `daemon_pid(data, envs)`.
- Produces: nothing other tasks use.

- [ ] **Step 1: Write the test**

Append to `crates/izba-cli/tests/daemon_e2e.rs`:

```rust
/// Can this process become root without a prompt? CI's hosted runners can.
#[cfg(target_os = "linux")]
fn passwordless_sudo() -> bool {
    std::process::Command::new("sudo")
        .args(["-n", "true"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// #231: `sudo izba` against a user-owned daemon is refused by the daemon's
/// peer-uid check (F-09). The client must say why, and must not fork a second
/// `izba daemon run`.
///
/// Needs a real second uid, so it runs as root via `sudo -n`. It boots no VM,
/// but lives behind `IZBA_INTEGRATION=1` because a test that escalates should
/// be an explicit opt-in. In GitHub Actions a missing `sudo -n` is a FAILURE,
/// not a skip — otherwise the gate could pass without ever running this.
#[cfg(target_os = "linux")]
#[test]
fn foreign_uid_client_is_refused_without_spawning_a_daemon() {
    use std::os::unix::fs::MetadataExt;

    if !want() {
        return;
    }
    if !passwordless_sudo() {
        assert!(
            std::env::var_os("GITHUB_ACTIONS").is_none(),
            "CI must run this test: `sudo -n true` failed on a GitHub runner"
        );
        eprintln!("SKIP: needs passwordless sudo for a real second uid");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("izba");
    let my_uid = std::fs::metadata(dir.path()).unwrap().uid();
    assert_ne!(my_uid, 0, "the test itself must not run as root");

    // Auto-start the user's daemon.
    assert_ok(&izba(&data, &[], &["ls"]), "ls (starts the daemon)");
    let pid = daemon_pid(&data, &[]).expect("daemon running");
    let log = data.join("daemon").join("daemon.log");

    let as_root = |args: &[&str]| {
        std::process::Command::new("sudo")
            .arg("-n")
            .arg("env")
            .arg(format!("IZBA_DATA_DIR={}", data.display()))
            .arg(env!("CARGO_BIN_EXE_izba"))
            .args(args)
            .output()
            .expect("run izba as root")
    };
    let refused = |o: &Output, what: &str| {
        let stderr = String::from_utf8_lossy(&o.stderr).into_owned();
        assert!(!o.status.success(), "{what} must fail as root: {stderr}");
        assert!(
            stderr.contains(&format!("belongs to uid {my_uid}")),
            "{what}: {stderr}"
        );
        assert!(stderr.contains("running as uid 0"), "{what}: {stderr}");
        assert!(stderr.contains("daemon.log"), "{what}: {stderr}");
        assert!(!stderr.contains("reading hello reply"), "{what}: {stderr}");
    };

    // The spawning entry point (`DaemonClient::connect`).
    refused(&as_root(&["ls"]), "sudo izba ls");
    let text = std::fs::read_to_string(&log).unwrap();
    assert_eq!(
        text.matches("rejected (daemon runs as uid").count(),
        1,
        "exactly one connection attempt — a client that respawns retries: {text}"
    );
    assert!(
        !text.contains("daemon already running"),
        "a stray `izba daemon run` was spawned: {text}"
    );

    // The strict entry point (`connect_existing`: status never spawns).
    refused(&as_root(&["daemon", "status"]), "sudo izba daemon status");

    // The owner's daemon is untouched and still serves its owner.
    assert_eq!(daemon_pid(&data, &[]), Some(pid), "daemon was replaced");
    assert_ok(&izba(&data, &[], &["ls"]), "ls as the owner afterwards");
    let text = std::fs::read_to_string(&log).unwrap();
    assert!(!text.contains("daemon already running"), "{text}");

    assert_ok(&izba(&data, &[], &["daemon", "stop"]), "daemon stop");
}
```

- [ ] **Step 2: Compile it and run it where possible**

Run: `cargo test -p izba-cli --test daemon_e2e --no-run 2>&1 | tail -5` — must compile.
Run: `cargo clippy -p izba-cli --all-targets -- -D warnings` and `cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-cli -- -D warnings` — clean (the test and helper are `cfg(target_os = "linux")`; if an import becomes unused on Windows, gate it the same way).
Run (Bash sandbox disabled): `IZBA_INTEGRATION=1 cargo test -p izba-cli --test daemon_e2e foreign_uid_client -- --nocapture 2>&1 | tail -20`
Expected: PASS where `sudo -n true` works; on this workstation `sudo -n` is unavailable, so the expected output is the `SKIP: needs passwordless sudo` line. Report honestly which one you saw — the controller runs it for real through the e2e workflow.

- [ ] **Step 3: Commit**

```bash
cargo fmt --check
git add crates/izba-cli/tests/daemon_e2e.rs
git commit -m "test(e2e): a root client is refused by a user-owned izbad without a stray spawn

Runs the real binary as root against a real user-owned daemon: the error
names both uids and the daemon log, the daemon sees exactly one
connection attempt, and no second 'izba daemon run' was started.

Refs #231"
```
