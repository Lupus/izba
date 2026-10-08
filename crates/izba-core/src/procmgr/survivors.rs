//! The FFI-free decision behind the Windows `tree_survivors` (#319): which
//! not-yet-signaled descendants of a recorded launcher may still be OUR VMM
//! workers. Kept platform-neutral so it is unit-tested on every host; the
//! Windows module gathers the inputs from the kernel and calls it.

/// One candidate process of the tree: its pid and creation time (FILETIME ticks).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Candidate {
    pub pid: u32,
    pub created: u64,
}

/// Pure filter behind the Windows `tree_survivors` (#319): drops the
/// candidates a recycled launcher pid could have dragged into the PPID walk.
///
/// Windows never rewrites a PPID, so once the launcher is dead its pid NUMBER
/// is all the walk has to go on, and anything whose PPID equals that number
/// (plus its children) is a candidate. Two facts separate our workers from a
/// stranger's processes:
///
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
    candidates: &[Candidate],
) -> Vec<u32> {
    if boot_time.is_some_and(|boot| root_starttime < boot) {
        return Vec::new();
    }
    candidates
        .iter()
        .filter(|c| pid_holder_created.is_none_or(|holder| c.created < holder))
        .map(|c| c.pid)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOOT: u64 = 1_000;
    const ROOT: u64 = 2_000;

    fn cands() -> Vec<Candidate> {
        vec![
            Candidate {
                pid: 30620,
                created: ROOT + 10,
            },
            Candidate {
                pid: 29588,
                created: ROOT + 20,
            },
        ]
    }

    #[test]
    fn a_launcher_started_before_the_current_boot_has_no_survivors() {
        assert!(
            filter_tree_survivors(BOOT - 1, Some(BOOT), None, &cands()).is_empty(),
            "nothing outlives a reboot, whatever claims the old pid as its parent"
        );
    }

    #[test]
    fn a_zero_starttime_record_reads_as_pre_boot() {
        assert!(filter_tree_survivors(0, Some(BOOT), None, &cands()).is_empty());
    }

    #[test]
    fn a_launcher_started_at_or_after_boot_keeps_its_candidates() {
        assert_eq!(
            filter_tree_survivors(BOOT, Some(BOOT), None, &cands()),
            vec![30620, 29588]
        );
        assert_eq!(
            filter_tree_survivors(ROOT, Some(BOOT), None, &cands()),
            vec![30620, 29588]
        );
    }

    #[test]
    fn an_unknown_boot_time_disables_the_boot_guard() {
        assert_eq!(
            filter_tree_survivors(0, None, None, &cands()),
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
            filter_tree_survivors(ROOT, Some(BOOT), Some(holder), &cands()),
            vec![30620]
        );
        assert!(
            filter_tree_survivors(ROOT, Some(BOOT), Some(ROOT + 5), &cands()).is_empty(),
            "every candidate is younger than the holder"
        );
    }

    #[test]
    fn candidates_older_than_the_pid_holder_are_kept() {
        assert_eq!(
            filter_tree_survivors(ROOT, Some(BOOT), Some(ROOT + 1_000), &cands()),
            vec![30620, 29588]
        );
    }

    #[test]
    fn no_pid_holder_keeps_every_candidate() {
        assert_eq!(
            filter_tree_survivors(ROOT, Some(BOOT), None, &cands()),
            vec![30620, 29588]
        );
    }

    #[test]
    fn no_candidates_means_no_survivors() {
        assert!(filter_tree_survivors(ROOT, Some(BOOT), None, &[]).is_empty());
    }
}
