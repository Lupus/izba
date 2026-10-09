//! The FFI-free decision behind the Windows `tree_survivors` (#319): which
//! not-yet-signaled descendants of a recorded launcher may still be OUR VMM
//! workers. Kept platform-neutral so it is unit-tested on every host; the
//! Windows module gathers the inputs from the kernel and calls it.

/// One candidate process of the tree: its pid, creation time (FILETIME ticks)
/// and image file name (Toolhelp's `szExeFile`: the bare file name, no
/// directory — e.g. `openvmm.exe`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Candidate {
    pub pid: u32,
    pub created: u64,
    pub image: String,
}

/// Pure filter behind the Windows `tree_survivors` (#319): drops the
/// candidates a recycled launcher pid could have dragged into the PPID walk.
///
/// Windows never rewrites a PPID, so once the launcher is dead its pid NUMBER
/// is all the walk has to go on, and anything whose PPID equals that number
/// (plus its children) is a candidate. Three facts separate our workers from a
/// stranger's processes:
///
/// - **Image guard** — `vmm_image` is the file name of the only VMM izba
///   launches (`openvmm.exe` on Windows); a candidate whose image is anything
///   else is never one of our workers, whatever its PPID or creation time,
///   and is dropped (compared ASCII-case-insensitively, as Windows file names
///   are). This is what keeps a STRANGER's process out once the pid is vacant
///   again: our launcher dies uncleanly, an unrelated program reuses its pid,
///   spawns a child and exits — now no process holds the pid, so guard (b)
///   has nothing to compare against, and the child's own creation time is
///   what `terminate_identity` would re-verify, so `stop`'s re-sweep would
///   kill someone else's background process. Residual: the guard cannot tell
///   two izba VMMs apart — if two STALE sandboxes' launcher pids were reused
///   by each other's launchers, both trees are `openvmm.exe` and one can
///   still report (and re-sweep) the other's workers. The full fix records
///   the worker identities in `state.json` at start (follow-up issue).
/// - (a) **Boot guard** — a launcher created before the current boot cannot
///   have a surviving tree: nothing outlives a reboot. `root_starttime <
///   boot_time` ⇒ `[]`. `boot_time` is `None` when it could not be read; the
///   guard is then DISABLED (every candidate kept), never estimated. The
///   asymmetry is deliberate: an estimate that placed boot too LATE would
///   declare a live tree pre-boot and report "stopped" while a worker still
///   holds the disks — the double-boot hole #319 closes. Disabling the guard
///   can only over-report, which is a loud, retryable refusal. (A record with
///   `starttime: 0` is pre-boot by construction and so reads as no tree.)
///   Clock assumption: process creation times are wall-clock stamps and are
///   not adjusted when the clock changes. If the clock is stepped BACK by Δ
///   after boot, launchers started within Δ of boot read as pre-boot and their
///   survivors are dropped — the unsafe direction. The robust form (recording
///   the boot identity in `state.json` at start and comparing by equality) is
///   tracked as #327.
/// - (b) **Pid-holder guard** — `pid_holder_created` is `Some(t)` when a
///   DIFFERENT process (creation time `t`) now holds the launcher's pid. Our
///   workers were created while our launcher was alive, i.e. before it died
///   and before anything could reuse its pid, so every one of them predates
///   `t`; a candidate created at or after `t` belongs to the new holder and
///   is dropped.
///
/// The recorded root itself is NOT a candidate — the caller matches it by its
/// exact creation time, which defeats pid reuse on its own.
pub(crate) fn filter_tree_survivors(
    root_starttime: u64,
    boot_time: Option<u64>,
    pid_holder_created: Option<u64>,
    vmm_image: &str,
    candidates: &[Candidate],
) -> Vec<u32> {
    if boot_time.is_some_and(|boot| root_starttime < boot) {
        return Vec::new();
    }
    candidates
        .iter()
        .filter(|c| c.image.eq_ignore_ascii_case(vmm_image))
        .filter(|c| pid_holder_created.is_none_or(|holder| c.created < holder))
        .map(|c| c.pid)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOOT: u64 = 1_000;
    const ROOT: u64 = 2_000;
    const VMM: &str = "openvmm.exe";

    fn cand(pid: u32, created: u64, image: &str) -> Candidate {
        Candidate {
            pid,
            created,
            image: image.into(),
        }
    }

    fn cands() -> Vec<Candidate> {
        vec![cand(30620, ROOT + 10, VMM), cand(29588, ROOT + 20, VMM)]
    }

    /// The finding the image guard closes: the launcher pid is vacant again
    /// (no holder) and the boot guard passes, so neither time guard can see
    /// that the child of a since-exited stranger is not ours — only its image.
    #[test]
    fn a_candidate_of_another_image_is_dropped_even_with_no_holder_and_no_boot_guard() {
        let mixed = vec![
            cand(30620, ROOT + 10, VMM),
            cand(4242, ROOT + 15, "backup-agent.exe"),
            cand(29588, ROOT + 20, VMM),
        ];
        assert_eq!(
            filter_tree_survivors(ROOT, Some(BOOT), None, VMM, &mixed),
            vec![30620, 29588],
            "only the VMM's own image can be a worker"
        );
        assert_eq!(
            filter_tree_survivors(ROOT, None, None, VMM, &mixed),
            vec![30620, 29588],
            "a disabled boot guard does not let a foreign image through either"
        );
        assert!(
            filter_tree_survivors(
                ROOT,
                Some(BOOT),
                None,
                VMM,
                &[cand(4242, ROOT + 15, "backup-agent.exe")]
            )
            .is_empty(),
            "a stranger's lone child is not a survivor"
        );
    }

    #[test]
    fn the_image_match_ignores_ascii_case() {
        assert_eq!(
            filter_tree_survivors(
                ROOT,
                Some(BOOT),
                None,
                VMM,
                &[cand(30620, ROOT + 10, "OpenVMM.EXE")]
            ),
            vec![30620]
        );
    }

    /// The image guard and the pid-holder guard are BOTH required: a VMM-image
    /// candidate younger than a new pid holder is still the holder's.
    #[test]
    fn a_vmm_image_does_not_override_the_pid_holder_guard() {
        assert!(filter_tree_survivors(
            ROOT,
            Some(BOOT),
            Some(ROOT + 5),
            VMM,
            &[cand(30620, ROOT + 10, VMM)]
        )
        .is_empty());
    }

    #[test]
    fn a_launcher_started_before_the_current_boot_has_no_survivors() {
        assert!(
            filter_tree_survivors(BOOT - 1, Some(BOOT), None, VMM, &cands()).is_empty(),
            "nothing outlives a reboot, whatever claims the old pid as its parent"
        );
    }

    #[test]
    fn a_zero_starttime_record_reads_as_pre_boot() {
        assert!(filter_tree_survivors(0, Some(BOOT), None, VMM, &cands()).is_empty());
    }

    #[test]
    fn a_launcher_started_at_or_after_boot_keeps_its_candidates() {
        assert_eq!(
            filter_tree_survivors(BOOT, Some(BOOT), None, VMM, &cands()),
            vec![30620, 29588]
        );
        assert_eq!(
            filter_tree_survivors(ROOT, Some(BOOT), None, VMM, &cands()),
            vec![30620, 29588]
        );
    }

    #[test]
    fn an_unknown_boot_time_disables_the_boot_guard() {
        assert_eq!(
            filter_tree_survivors(0, None, None, VMM, &cands()),
            vec![30620, 29588],
            "unknown boot must over-report, never guess the tree away"
        );
    }

    #[test]
    fn candidates_created_at_or_after_a_new_pid_holder_are_dropped() {
        let holder = ROOT + 20;
        // 30620 predates the holder (ours); 29588 was created at the very
        // tick the holder was — not ours.
        assert_eq!(
            filter_tree_survivors(ROOT, Some(BOOT), Some(holder), VMM, &cands()),
            vec![30620]
        );
        assert!(
            filter_tree_survivors(ROOT, Some(BOOT), Some(ROOT + 5), VMM, &cands()).is_empty(),
            "every candidate is younger than the holder"
        );
    }

    #[test]
    fn candidates_older_than_the_pid_holder_are_kept() {
        assert_eq!(
            filter_tree_survivors(ROOT, Some(BOOT), Some(ROOT + 1_000), VMM, &cands()),
            vec![30620, 29588]
        );
    }

    #[test]
    fn no_pid_holder_keeps_every_candidate() {
        assert_eq!(
            filter_tree_survivors(ROOT, Some(BOOT), None, VMM, &cands()),
            vec![30620, 29588]
        );
    }

    #[test]
    fn no_candidates_means_no_survivors() {
        assert!(filter_tree_survivors(ROOT, Some(BOOT), None, VMM, &[]).is_empty());
    }
}
