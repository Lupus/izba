//! Differential confinement proof-of-concept for the Windows VMM jailer.
//!
//! This example is the CI artifact that PROVES the host-side confinement
//! (`spawn_confined`: restricted token + Low integrity + job + mitigations)
//! actually blocks the security-relevant operations it is meant to block, while
//! NOT breaking the one capability the VMM needs (WHP). It is the concrete
//! evidence for security finding F-06 ("unjailed VMM") on Windows.
//!
//! It runs in two roles:
//!
//! - `confine_probe child --attempt <kind> --result <file> --nonce <hex>
//!   [--target <path>]` performs one abuse case and records `<nonce>:<verdict>`
//!   into `<file>` (verdict is `OK`/`DENIED`, or for `self-il` the integrity
//!   level name `LOW`/`MEDIUM`/`OTHER`), also mirroring the OK/DENIED outcome
//!   into the process exit code (0 = OK, 13 = DENIED).
//! - `confine_probe harness` is the differential driver: for each attempt it
//!   runs the child CONFINED and UNCONFINED, then asserts the security-relevant
//!   attempts are DENIED-under-confinement / OK-without, that the WHP capability
//!   gate stays OK under BOTH (skipped if WHP is absent on the host), and that
//!   the `self-il` positive control reports Low confined / Medium unconfined. A
//!   vacuous run (the unconfined leg did not even succeed) is a FAIL, so the
//!   differential is always meaningful.
//!
//! The result file is written as `<nonce>:<payload>`; the harness generates a
//! fresh per-spawn nonce and REQUIRES it to match what it reads back, so a
//! stale/leftover file can never be mistaken for a fresh verdict (defeats a
//! wrongly-green gate).
//!
//! The whole Windows body is `#[cfg(windows)]`; the Linux build compiles a
//! no-op so the example stays in the cross-checked surface.

#[cfg(not(windows))]
fn main() {
    eprintln!("confine_probe: windows-only");
}

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    win::main()
}

#[cfg(windows)]
mod win {
    use izba_core::procmgr::confine::ConfinementPolicy;
    use izba_core::procmgr::{
        pid_alive, set_low_integrity_recursive, spawn_confined, spawn_detached,
    };
    use izba_core::vmm::CommandSpec;
    use std::path::{Path, PathBuf};
    use std::process::ExitCode;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::OnceLock;
    use std::time::{Duration, Instant};

    /// Result-file / exit-code sentinels shared by the two roles.
    const OK: &str = "OK";
    const DENIED: &str = "DENIED";
    const EXIT_DENIED: u8 = 13;

    /// `self-il` integrity-level payload names (written after the nonce).
    const IL_LOW: &str = "LOW";
    const IL_MEDIUM: &str = "MEDIUM";
    const IL_HIGH: &str = "HIGH";
    const IL_OTHER: &str = "OTHER";

    /// Mandatory-label RIDs (winnt.h `SECURITY_MANDATORY_*_RID`). Not exported by
    /// windows-sys, so defined locally (same pattern as `SE_GROUP_INTEGRITY` in
    /// `jail_windows.rs`).
    const SECURITY_MANDATORY_LOW_RID: u32 = 0x0000_1000; // 4096
    const SECURITY_MANDATORY_MEDIUM_RID: u32 = 0x0000_2000; // 8192
    const SECURITY_MANDATORY_HIGH_RID: u32 = 0x0000_3000; // 12288 (elevated)

    /// The abuse cases. `write-up` and `acquire-priv` are SECURITY gates (must be
    /// blocked under confinement, allowed without); `whp` is the CAPABILITY gate
    /// (must stay allowed under BOTH — confinement must not break the hypervisor —
    /// but skipped when WHP is absent); `self-il` is the positive control proving
    /// confinement lowered the token integrity to Low.
    const SECURITY_ATTEMPTS: &[&str] = &["write-up", "acquire-priv"];
    const CAPABILITY_ATTEMPTS: &[&str] = &["whp"];

    /// Total wall-clock budget for the whole harness run, shared across all legs.
    /// A single global deadline (not a per-leg cap) means a stuck leg can't hang
    /// CI indefinitely while still letting fast legs run unconstrained.
    const GLOBAL_BUDGET: Duration = Duration::from_secs(90);

    pub fn main() -> ExitCode {
        let mut args = std::env::args().skip(1);
        match args.next().as_deref() {
            Some("child") => child(args.collect()),
            Some("harness") | None => harness(),
            Some(other) => {
                eprintln!("confine_probe: unknown role {other:?} (expected child|harness)");
                ExitCode::from(2)
            }
        }
    }

    // ---- child role ---------------------------------------------------------

    /// Parse `--attempt <kind> --result <file> --nonce <hex> [--target <path>]`,
    /// run the attempt, write `<nonce>:<payload>`, exit 0/13 accordingly.
    fn child(args: Vec<String>) -> ExitCode {
        let mut attempt = None;
        let mut result = None;
        let mut nonce = None;
        let mut target = None;
        let mut it = args.into_iter();
        while let Some(a) = it.next() {
            match a.as_str() {
                "--attempt" => attempt = it.next(),
                "--result" => result = it.next(),
                "--nonce" => nonce = it.next(),
                "--target" => target = it.next(),
                other => {
                    eprintln!("confine_probe child: unexpected arg {other:?}");
                    return ExitCode::from(2);
                }
            }
        }
        let (Some(attempt), Some(result), Some(nonce)) = (attempt, result, nonce) else {
            eprintln!("confine_probe child: --attempt, --result and --nonce are required");
            return ExitCode::from(2);
        };

        // `self-il` reports the integrity-level name, not an OK/DENIED verdict;
        // the others map a boolean "operation allowed?" to OK/DENIED.
        if attempt == "self-il" {
            let payload = self_integrity_name();
            // self-il always "succeeds" (it only reads its own token); exit 0.
            if let Err(e) = std::fs::write(&result, format!("{nonce}:{payload}")) {
                eprintln!("confine_probe child: writing result {result}: {e}");
                return ExitCode::from(2);
            }
            return ExitCode::from(0);
        }

        let allowed = match attempt.as_str() {
            "write-up" => {
                let Some(t) = target else {
                    eprintln!("confine_probe child: write-up requires --target");
                    return ExitCode::from(2);
                };
                attempt_write_up(Path::new(&t))
            }
            "acquire-priv" => attempt_acquire_priv(),
            "whp" => attempt_whp(),
            other => {
                eprintln!("confine_probe child: unknown attempt {other:?}");
                return ExitCode::from(2);
            }
        };

        let verdict = if allowed { OK } else { DENIED };
        // Even though the exit code carries the OK/DENIED verdict, the harness
        // reads the nonce-tagged file (and requires the nonce to match), so a
        // write error must surface as a hard failure here.
        if let Err(e) = std::fs::write(&result, format!("{nonce}:{verdict}")) {
            eprintln!("confine_probe child: writing result {result}: {e}");
            return ExitCode::from(2);
        }
        if allowed {
            ExitCode::from(0)
        } else {
            ExitCode::from(EXIT_DENIED)
        }
    }

    /// write-up: try to create+write a file at a Medium-IL location the harness
    /// prepared. A Low-IL confined child cannot write a Medium-IL object (the
    /// mandatory-label no-write-up policy) and gets ACCESS_DENIED; an unconfined
    /// Medium child succeeds. Returns true iff the write SUCCEEDED.
    fn attempt_write_up(target: &Path) -> bool {
        match std::fs::File::create(target) {
            Ok(mut f) => {
                use std::io::Write;
                // Actually write so we exercise data flow, not just object create.
                f.write_all(b"izba-confine-probe").is_ok()
            }
            Err(_) => false, // ACCESS_DENIED (and any other failure) => DENIED
        }
    }

    /// acquire-priv: try to ENABLE SeShutdownPrivilege on our own token. Under
    /// `DISABLE_MAX_PRIVILEGE` the privilege is REMOVED from the token, so
    /// AdjustTokenPrivileges returns success-with-`ERROR_NOT_ALL_ASSIGNED` ->
    /// DENIED. A normal token has the privilege -> enabled, GetLastError==0 -> OK.
    /// Returns true iff the privilege was actually enabled.
    fn attempt_acquire_priv() -> bool {
        use windows_sys::Win32::Foundation::{
            CloseHandle, GetLastError, ERROR_SUCCESS, HANDLE, LUID,
        };
        use windows_sys::Win32::Security::{
            AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES,
            SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        // SAFETY: linear FFI; the opened token handle is closed on every path.
        unsafe {
            let mut tok: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut tok,
            ) == 0
            {
                return false;
            }
            let enabled = (|| {
                let name: Vec<u16> = "SeShutdownPrivilege\0".encode_utf16().collect();
                let mut luid: LUID = std::mem::zeroed();
                if LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &mut luid) == 0 {
                    return false;
                }
                let tp = TOKEN_PRIVILEGES {
                    PrivilegeCount: 1,
                    Privileges: [LUID_AND_ATTRIBUTES {
                        Luid: luid,
                        Attributes: SE_PRIVILEGE_ENABLED,
                    }],
                };
                // AdjustTokenPrivileges returns nonzero even on partial failure;
                // the real verdict is GetLastError: ERROR_NOT_ALL_ASSIGNED means
                // the privilege was not in the token (removed by DISABLE_MAX_PRIVILEGE).
                let ok = AdjustTokenPrivileges(
                    tok,
                    0,
                    &tp,
                    std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                );
                ok != 0 && GetLastError() == ERROR_SUCCESS
            })();
            CloseHandle(tok);
            enabled
        }
    }

    /// whp: open then close a Windows Hypervisor Platform partition. This is the
    /// capability gate — confinement must NOT break WHP, so this must be OK under
    /// both confined and unconfined. Returns true iff `WHvCreatePartition`
    /// succeeded (S_OK). The partition is always deleted on success.
    fn attempt_whp() -> bool {
        use windows_sys::Win32::System::Hypervisor::{
            WHvCreatePartition, WHvDeletePartition, WHV_PARTITION_HANDLE,
        };
        // S_OK is 0; WHvCreatePartition returns an HRESULT.
        let mut part: WHV_PARTITION_HANDLE = 0;
        // SAFETY: single out-pointer; the partition is deleted iff created.
        unsafe {
            let hr = WHvCreatePartition(&mut part);
            if hr == 0 {
                WHvDeletePartition(part);
                true
            } else {
                false
            }
        }
    }

    /// self-il: query our OWN token integrity level and return its name. This is
    /// the positive control: a confined child must report `LOW` while the
    /// unconfined one reports a HIGHER level (`MEDIUM` normally, or `HIGH` when
    /// the harness itself runs elevated — e.g. CI runners), directly proving
    /// `spawn_confined` LOWERED the IL (decoupled from the %TEMP%-labeling the
    /// write-up gate relies on).
    fn self_integrity_name() -> &'static str {
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
        use windows_sys::Win32::Security::{
            GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TokenIntegrityLevel,
            TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        // SAFETY: linear FFI; the token handle is closed on every path and the
        // label buffer outlives the SID pointers we read out of it.
        unsafe {
            let mut tok: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) == 0 {
                return IL_OTHER;
            }
            let rid = (|| -> Option<u32> {
                // Size the TokenIntegrityLevel buffer (TOKEN_MANDATORY_LABEL plus
                // the trailing SID). First call fails with ERROR_INSUFFICIENT_BUFFER
                // and fills `needed`.
                let mut needed: u32 = 0;
                GetTokenInformation(
                    tok,
                    TokenIntegrityLevel,
                    std::ptr::null_mut(),
                    0,
                    &mut needed,
                );
                if needed == 0 {
                    return None;
                }
                let mut buf = vec![0u8; needed as usize];
                if GetTokenInformation(
                    tok,
                    TokenIntegrityLevel,
                    buf.as_mut_ptr() as *mut _,
                    needed,
                    &mut needed,
                ) == 0
                {
                    return None;
                }
                let label = &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
                let sid = label.Label.Sid;
                if sid.is_null() {
                    return None;
                }
                // The IL RID is the LAST sub-authority of the label SID.
                let count_ptr = GetSidSubAuthorityCount(sid);
                if count_ptr.is_null() {
                    return None;
                }
                let count = *count_ptr;
                if count == 0 {
                    return None;
                }
                let rid_ptr = GetSidSubAuthority(sid, (count - 1) as u32);
                if rid_ptr.is_null() {
                    return None;
                }
                Some(*rid_ptr)
            })();
            CloseHandle(tok);
            match rid {
                Some(SECURITY_MANDATORY_LOW_RID) => IL_LOW,
                Some(SECURITY_MANDATORY_MEDIUM_RID) => IL_MEDIUM,
                Some(SECURITY_MANDATORY_HIGH_RID) => IL_HIGH,
                _ => IL_OTHER,
            }
        }
    }

    /// One-shot host WHP-presence precheck used by the harness to SKIP the `whp`
    /// gate when no hypervisor is present (so "WHP absent" is not conflated with
    /// "confinement broke WHP"). On the real windows-whp e2e runner WHP IS
    /// present, so this returns true there and the gate runs normally.
    fn whp_present() -> bool {
        use windows_sys::Win32::System::Hypervisor::{
            WHvCapabilityCodeHypervisorPresent, WHvGetCapability,
        };
        // WHvGetCapability fills a BOOL (4 bytes) for HypervisorPresent.
        let mut present: u32 = 0;
        let mut written: u32 = 0;
        // SAFETY: single fixed-size out-buffer + written-count out-pointer.
        unsafe {
            let hr = WHvGetCapability(
                WHvCapabilityCodeHypervisorPresent,
                &mut present as *mut u32 as *mut _,
                std::mem::size_of::<u32>() as u32,
                &mut written,
            );
            hr == 0 && written >= std::mem::size_of::<u32>() as u32 && present != 0
        }
    }

    // ---- harness role -------------------------------------------------------

    /// Outcome of running one child leg: the payload after the verified nonce.
    struct Leg {
        verdict: String,
    }

    fn harness() -> ExitCode {
        let exe = match std::env::current_exe() {
            Ok(e) => e,
            Err(e) => {
                eprintln!("confine_probe harness: current_exe: {e}");
                return ExitCode::from(2);
            }
        };
        let log = std::env::temp_dir().join("izba-confine-probe.log");
        // Single global deadline for the whole run (Fix 4): no leg may push the
        // run past this, and a stuck child fails its leg with diagnostics.
        let deadline = Instant::now() + GLOBAL_BUDGET;

        let mut all_pass = true;
        println!("izba confine_probe — differential confinement PoC (F-06 Windows)");
        println!(
            "{a:<14} {c:<16} {u:<16} verdict",
            a = "attempt",
            c = "confined",
            u = "unconfined"
        );

        for &attempt in SECURITY_ATTEMPTS.iter().chain(CAPABILITY_ATTEMPTS) {
            let security = SECURITY_ATTEMPTS.contains(&attempt);

            // WHP capability precheck (Fix 2): if the hypervisor is absent, SKIP
            // the whp gate — neither a pass nor a fail; it's neutral.
            if attempt == "whp" && !whp_present() {
                println!(
                    "{attempt:<14} {:<16} {:<16} SKIPPED (WHP not present on this host)",
                    "-", "-"
                );
                continue;
            }

            let row = run_attempt(&exe, &log, attempt, deadline);
            let (confined, unconfined) = match row {
                Ok(pair) => pair,
                Err(e) => {
                    println!("{attempt:<14} {:<16} {:<16} FAIL ({e})", "-", "-");
                    all_pass = false;
                    continue;
                }
            };

            let pass = if security {
                // SECURITY gate: must be DENIED confined AND OK unconfined.
                // The unconfined==OK clause defeats a vacuous test (e.g. the op
                // failing for an incidental reason rather than the confinement).
                confined.verdict == DENIED && unconfined.verdict == OK
            } else {
                // CAPABILITY gate: confinement must not break it.
                confined.verdict == OK && unconfined.verdict == OK
            };
            if !pass {
                all_pass = false;
            }
            println!(
                "{attempt:<14} {:<16} {:<16} {}",
                confined.verdict,
                unconfined.verdict,
                if pass { "PASS" } else { "FAIL" },
            );
            if !pass {
                let want = if security {
                    "expected confined=DENIED unconfined=OK"
                } else {
                    "expected confined=OK unconfined=OK"
                };
                println!("    -> {want}");
            }
        }

        // self-il positive control (Fix 3): its own row, asserting the
        // confinement lowered the token IL (confined=LOW, unconfined=MEDIUM).
        match run_attempt(&exe, &log, "self-il", deadline) {
            Ok((confined, unconfined)) => {
                // The control proves confinement LOWERED the IL: confined must be
                // Low and the unconfined baseline must be a higher KNOWN level —
                // Medium normally, or High when the harness runs elevated (CI).
                let pass = confined.verdict == IL_LOW
                    && (unconfined.verdict == IL_MEDIUM || unconfined.verdict == IL_HIGH);
                if !pass {
                    all_pass = false;
                }
                println!(
                    "self-il        confined={:<8} unconfined={:<8} -> {}",
                    confined.verdict,
                    unconfined.verdict,
                    if pass { "PASS" } else { "FAIL" },
                );
                if !pass {
                    println!("    -> expected confined=LOW unconfined=MEDIUM-or-HIGH");
                }
            }
            Err(e) => {
                println!("self-il        {:<16} {:<16} FAIL ({e})", "-", "-");
                all_pass = false;
            }
        }

        if all_pass {
            println!("confine_probe: ALL attempts passed");
            ExitCode::from(0)
        } else {
            println!("confine_probe: FAILURES present — confinement differential not satisfied");
            ExitCode::from(1)
        }
    }

    /// Run one attempt both confined and unconfined; return (confined, unconfined).
    /// For `write-up`, a SINGLE harness-owned Medium-IL target object is created
    /// here and passed to BOTH legs, so unconfined==OK is a true positive control
    /// for the exact object the confined leg was denied (Fix 3).
    fn run_attempt(
        exe: &Path,
        log: &Path,
        attempt: &str,
        deadline: Instant,
    ) -> anyhow::Result<(Leg, Leg)> {
        // Shared write-up target: one Medium-IL object reused by both legs.
        let target = if attempt == "write-up" {
            let dir = unique_temp("izba-cp-target");
            std::fs::create_dir_all(&dir)?;
            Some(dir.join("write-up-target.bin"))
        } else {
            None
        };

        // Run both legs; clean up the shared target dir afterwards regardless of
        // outcome so a failing leg never leaks the Medium-IL object.
        let confined = run_leg(exe, log, attempt, true, target.as_deref(), deadline);
        let unconfined = run_leg(exe, log, attempt, false, target.as_deref(), deadline);

        if let Some(t) = &target {
            let _ = std::fs::remove_file(t);
            if let Some(parent) = t.parent() {
                let _ = std::fs::remove_dir_all(parent);
            }
        }

        Ok((confined?, unconfined?))
    }

    /// Spawn the child for `attempt` (confined or not), wait for it to die (within
    /// the GLOBAL `deadline`), and read its nonce-tagged verdict back. The nonce
    /// the harness generated MUST match the file's leading `<nonce>:`; a mismatch,
    /// missing file, or garbage is a hard FAIL — ties the verdict to THIS spawn so
    /// a stale/leftover file can never read as a fresh pass (Fix 1).
    fn run_leg(
        exe: &Path,
        log: &Path,
        attempt: &str,
        confined: bool,
        target: Option<&Path>,
        deadline: Instant,
    ) -> anyhow::Result<Leg> {
        let tag = if confined { "confined" } else { "unconfined" };
        // The verdict file lives in the Low-labelled result dir so a confined
        // (Low-IL) child can actually write it; NOT in the Medium %TEMP%.
        let result = unique_result(&format!("izba-cp-{attempt}-{tag}-result"));
        // Clean any stale file so a missing write is detectable.
        let _ = std::fs::remove_file(&result);
        // Fresh per-spawn nonce (Fix 1): pid + monotonic counter + high-res clock.
        let nonce = unique_nonce();

        let mut argv = vec![
            path_string(exe)?,
            "child".into(),
            "--attempt".into(),
            attempt.into(),
            "--result".into(),
            path_string(&result)?,
            "--nonce".into(),
            nonce.clone(),
        ];
        if attempt == "write-up" {
            let target = target.ok_or_else(|| {
                anyhow::anyhow!("write-up requires a shared --target from run_attempt")
            })?;
            argv.push("--target".into());
            argv.push(path_string(target)?);
        }

        let spec = CommandSpec { argv };
        let id = if confined {
            let (id, _mode) = spawn_confined(&spec, log, &ConfinementPolicy::vmm_default())?;
            id
        } else {
            spawn_detached(&spec, log)?
        };

        // Poll for death against the GLOBAL deadline (Fix 4). On timeout, FAIL
        // the leg with the tail of the child log so CI shows WHY it hung.
        while pid_alive(&id) {
            if Instant::now() >= deadline {
                anyhow::bail!(
                    "{attempt} ({tag}) child did not exit before the global {}s deadline\n--- child log tail ({}) ---\n{}",
                    GLOBAL_BUDGET.as_secs(),
                    log.display(),
                    log_tail(log),
                );
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        let raw = std::fs::read_to_string(&result).map_err(|e| {
            anyhow::anyhow!(
                "{attempt} ({tag}): no result file {} ({e}) — child likely failed to start \
                 or was killed before writing",
                result.display()
            )
        })?;
        let raw = raw.trim();
        let _ = std::fs::remove_file(&result);

        // Nonce gate (Fix 1): the file MUST be `<nonce>:<payload>` with OUR nonce.
        let Some((got_nonce, payload)) = raw.split_once(':') else {
            anyhow::bail!("{attempt} ({tag}): result {raw:?} is not <nonce>:<payload>");
        };
        if got_nonce != nonce {
            anyhow::bail!(
                "{attempt} ({tag}): nonce mismatch — got {got_nonce:?}, expected {nonce:?} \
                 (stale/leftover result file?)"
            );
        }

        // Validate the payload shape per attempt kind.
        if attempt == "self-il" {
            if ![IL_LOW, IL_MEDIUM, IL_HIGH, IL_OTHER].contains(&payload) {
                anyhow::bail!("{attempt} ({tag}): unexpected integrity payload {payload:?}");
            }
        } else if payload != OK && payload != DENIED {
            anyhow::bail!("{attempt} ({tag}): unexpected verdict {payload:?}");
        }

        Ok(Leg {
            verdict: payload.to_string(),
        })
    }

    /// Best-effort tail of the child log (last ~2 KiB) for timeout diagnostics.
    fn log_tail(log: &Path) -> String {
        match std::fs::read_to_string(log) {
            Ok(s) => {
                const MAX: usize = 2048;
                if s.len() > MAX {
                    format!("…{}", &s[s.len() - MAX..])
                } else {
                    s
                }
            }
            Err(e) => format!("(could not read log: {e})"),
        }
    }

    /// A fresh, process+time unique path under the system temp dir.
    fn unique_temp(stem: &str) -> PathBuf {
        std::env::temp_dir().join(format!("{stem}-{}-{}", std::process::id(), entropy()))
    }

    /// A per-process result directory, **Low-labelled** so a CONFINED (Low-IL)
    /// child can write its verdict file here. The Medium `%TEMP%` is itself NOT
    /// writable by a Low-IL process — that is the very no-write-up barrier this
    /// probe demonstrates — so the verdict IPC channel must be lowered, or every
    /// confined leg fails to report. The write-up *target* (the object whose
    /// denial we assert) stays at Medium; only this verdict channel is lowered.
    fn result_dir() -> &'static Path {
        static DIR: OnceLock<PathBuf> = OnceLock::new();
        DIR.get_or_init(|| {
            let d = std::env::temp_dir().join(format!("izba-cp-results-{}", std::process::id()));
            let _ = std::fs::create_dir_all(&d);
            // Best-effort: if labelling fails the confined legs fail loudly with
            // "no result file", which correctly surfaces the broken channel.
            let _ = set_low_integrity_recursive(&d);
            d
        })
        .as_path()
    }

    /// A fresh, unique verdict-file path inside the Low-labelled [`result_dir`].
    fn unique_result(stem: &str) -> PathBuf {
        result_dir().join(format!("{stem}-{}-{}", std::process::id(), entropy()))
    }

    /// A unique hex nonce per call: pid + monotonic counter + high-res clock, so
    /// no two spawns (across legs or attempts) can collide (Fix 1).
    fn unique_nonce() -> String {
        format!("{:08x}{:016x}", std::process::id(), entropy())
    }

    /// Monotonically increasing per-call entropy: a static counter folded with the
    /// high-res clock. Shared by `unique_temp` and `unique_nonce`.
    fn entropy() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        // Fold the counter into the high bits so the value is unique per call even
        // if the clock resolution repeats within a tight loop.
        nanos ^ (n.wrapping_mul(0x9E37_79B9_7F4A_7C15))
    }

    fn path_string(p: &Path) -> anyhow::Result<String> {
        p.to_str()
            .map(str::to_owned)
            .ok_or_else(|| anyhow::anyhow!("non-UTF-8 path: {}", p.display()))
    }
}
