//! The daemon's in-memory view of sandboxes. NOT authoritative — disk state
//! (sandbox dirs + pid identity) remains the source of truth; this is a
//! cache rebuilt at adoption and refreshed by the supervisor tick and by
//! lifecycle handlers, so `List`/`Status` answer without re-probing.
//!
//! `replace_all` merges a disk scan's result rather than swapping it in
//! wholesale, guarded by a `snapshot()`/generation pair: a handler write
//! that lands while the scan is in flight is never clobbered by the (by
//! then stale) scan result. See `replace_all`'s doc comment for the merge
//! rules.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::daemon::proto::SandboxSummary;
use crate::liveness::Liveness;
use crate::sandbox::SandboxInfo;

#[derive(Debug, Clone)]
struct Entry {
    image_ref: String,
    liveness: Liveness,
    /// `gen` at the time this entry was last written by `set`/`set_liveness`.
    /// Lets `replace_all` tell a handler write that landed after a scan
    /// began apart from one that predates it.
    mutated: u64,
}

#[derive(Default)]
struct Inner {
    entries: HashMap<String, Entry>,
    /// Tombstones for `remove`d names, keyed by the `gen` the removal
    /// happened at. Consulted (and trimmed) by `replace_all` so a
    /// pre-removal scan can't resurrect a sandbox that was removed while
    /// the scan was in flight.
    removed: HashMap<String, u64>,
    gen: u64,
}

#[derive(Default)]
pub struct Registry {
    inner: Mutex<Inner>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&self, name: &str, image_ref: &str, liveness: Liveness) {
        let mut inner = self.inner.lock().unwrap();
        inner.gen += 1;
        let gen = inner.gen;
        inner.removed.remove(name); // re-created sandboxes must live
        inner.entries.insert(
            name.to_string(),
            Entry {
                image_ref: image_ref.to_string(),
                liveness,
                mutated: gen,
            },
        );
    }

    /// Update liveness only; no-op for unknown names.
    pub fn set_liveness(&self, name: &str, liveness: Liveness) {
        let mut inner = self.inner.lock().unwrap();
        inner.gen += 1;
        let gen = inner.gen;
        if let Some(e) = inner.entries.get_mut(name) {
            e.liveness = liveness;
            e.mutated = gen;
        }
    }

    pub fn remove(&self, name: &str) {
        let mut inner = self.inner.lock().unwrap();
        inner.gen += 1;
        let gen = inner.gen;
        if inner.entries.remove(name).is_some() {
            inner.removed.insert(name.to_string(), gen);
        }
    }

    pub fn liveness(&self, name: &str) -> Option<Liveness> {
        self.inner
            .lock()
            .unwrap()
            .entries
            .get(name)
            .map(|e| e.liveness.clone())
    }

    /// Sandboxes with a live VMM (Running or Degraded) — drives idle-exit.
    pub fn running_count(&self) -> usize {
        self.inner
            .lock()
            .unwrap()
            .entries
            .values()
            .filter(|e| e.liveness != Liveness::Stopped)
            .count()
    }

    /// Names of sandboxes whose liveness is NOT Stopped (Running or Degraded),
    /// sorted alphabetically. Used to populate the managed SSH config.
    pub fn running_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .inner
            .lock()
            .unwrap()
            .entries
            .iter()
            .filter(|(_, e)| e.liveness != Liveness::Stopped)
            .map(|(name, _)| name.clone())
            .collect();
        names.sort();
        names
    }

    pub fn summaries(&self) -> Vec<SandboxSummary> {
        let mut out: Vec<SandboxSummary> = self
            .inner
            .lock()
            .unwrap()
            .entries
            .iter()
            .map(|(name, e)| SandboxSummary {
                name: name.clone(),
                image_ref: e.image_ref.clone(),
                status: e.liveness.describe(),
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    /// Current write generation. Callers about to run a `sandbox::list`
    /// disk scan take a snapshot BEFORE the scan starts and pass it to the
    /// matching `replace_all`, so the merge below can tell "this entry was
    /// already stale when the scan began" from "a handler wrote this while
    /// the scan was in flight".
    pub fn snapshot(&self) -> u64 {
        self.inner.lock().unwrap().gen
    }

    /// Merge a fresh disk-scan result in place of a wholesale swap
    /// (adoption, supervisor tick). `snapshot` must be the value `snapshot()`
    /// returned immediately before the `sandbox::list` call that produced
    /// `infos` — it draws the line between "stale" (scan predates it) and
    /// "fresh" (a handler wrote it while the scan was in flight, so the
    /// scan can't have seen it and must not clobber it):
    ///
    /// 1. an existing entry with `mutated > snapshot` is kept as-is —
    ///    whatever the incoming info says, a handler wrote it after the
    ///    scan began;
    /// 2. an incoming entry tombstoned (`removed`) after `snapshot` is
    ///    skipped — the sandbox was removed after the scan began, so the
    ///    scan's sighting of it must not resurrect it (rule 1 takes
    ///    precedence over this: a same-named `set` after the `remove`
    ///    clears the tombstone, so an entry that exists is never dropped
    ///    on account of an older tombstone);
    /// 3. an existing entry absent from `infos` with `mutated > snapshot`
    ///    is kept — it was created/registered after the scan began, so its
    ///    absence from `infos` is expected, not evidence it died;
    /// 4. everything else takes the incoming info — the normal refresh
    ///    path, including correcting stale cache entries for sandboxes
    ///    that died since the last tick.
    ///
    /// Tombstones with `gen <= snapshot` are trimmed once consulted. This
    /// is safe only because `replace_all` calls are serialized (adoption
    /// runs to completion before the supervisor thread is spawned, and
    /// only that one thread ticks afterwards) — a concurrent `replace_all`
    /// with an older snapshot could otherwise still need a tombstone this
    /// call just trimmed.
    pub fn replace_all(&self, snapshot: u64, infos: Vec<SandboxInfo>) {
        let mut inner = self.inner.lock().unwrap();
        let mut fresh: HashMap<String, Entry> = HashMap::with_capacity(infos.len());
        let mut seen: std::collections::HashSet<String> =
            std::collections::HashSet::with_capacity(infos.len());

        for info in infos {
            seen.insert(info.name.clone());
            if let Some(existing) = inner.entries.get(&info.name) {
                if existing.mutated > snapshot {
                    // Rule 1: a handler wrote this after the scan began.
                    fresh.insert(info.name.clone(), existing.clone());
                    continue;
                }
            } else if let Some(&removed_gen) = inner.removed.get(&info.name) {
                if removed_gen > snapshot {
                    // Rule 2: removed after the scan began — don't resurrect.
                    continue;
                }
            }
            // Rule 4: normal refresh.
            fresh.insert(
                info.name,
                Entry {
                    image_ref: info.image_ref,
                    liveness: info.liveness,
                    mutated: snapshot,
                },
            );
        }

        // Rule 3: entries created/registered after the scan began that the
        // scan couldn't have seen.
        for (name, entry) in inner.entries.iter() {
            if !seen.contains(name) && entry.mutated > snapshot {
                fresh.insert(name.clone(), entry.clone());
            }
        }

        inner.removed.retain(|_, gen| *gen > snapshot);
        inner.entries = fresh;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::liveness::Liveness;

    #[test]
    fn set_summaries_remove() {
        let r = Registry::new();
        assert!(r.summaries().is_empty());
        assert_eq!(r.running_count(), 0);

        r.set("web", "ubuntu:24.04", Liveness::Running);
        r.set("db", "postgres:16", Liveness::Stopped);
        r.set(
            "api",
            "alpine:3.20",
            Liveness::Degraded("sidecar virtiofsd:workspace died".into()),
        );

        let s = r.summaries();
        // Sorted by name.
        assert_eq!(
            s.iter().map(|x| x.name.as_str()).collect::<Vec<_>>(),
            vec!["api", "db", "web"]
        );
        assert_eq!(s[2].status, "running");
        assert_eq!(s[0].status, "degraded (sidecar virtiofsd:workspace died)");
        // Degraded counts as running (a VMM process exists to supervise).
        assert_eq!(r.running_count(), 2);
        assert_eq!(r.liveness("web"), Some(Liveness::Running));
        assert_eq!(r.liveness("nope"), None);

        r.set_liveness("web", Liveness::Stopped);
        assert_eq!(r.running_count(), 1);
        r.set_liveness("ghost", Liveness::Running); // no-op for unknown names
        assert_eq!(r.running_count(), 1);

        r.remove("db");
        assert_eq!(r.summaries().len(), 2);
    }

    #[test]
    fn running_names_returns_non_stopped_sorted() {
        let r = Registry::new();
        assert!(r.running_names().is_empty());

        r.set("web", "ubuntu:24.04", Liveness::Running);
        r.set("db", "postgres:16", Liveness::Stopped);
        r.set(
            "api",
            "alpine:3.20",
            Liveness::Degraded("sidecar died".into()),
        );
        r.set("cache", "redis:7", Liveness::Stopped);

        let names = r.running_names();
        // Only Running + Degraded; Stopped excluded; sorted.
        assert_eq!(names, vec!["api", "web"]);

        // After stopping "web", only "api" remains.
        r.set_liveness("web", Liveness::Stopped);
        assert_eq!(r.running_names(), vec!["api"]);

        // After removing "api", result is empty.
        r.remove("api");
        assert!(r.running_names().is_empty());
    }

    #[test]
    fn replace_all_swaps_the_view() {
        let r = Registry::new();
        r.set("old", "x", Liveness::Running);
        let snap = r.snapshot();
        r.replace_all(
            snap,
            vec![crate::sandbox::SandboxInfo {
                name: "new".into(),
                image_ref: "y".into(),
                liveness: Liveness::Stopped,
            }],
        );
        let s = r.summaries();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].name, "new");
    }

    fn info(name: &str, liveness: Liveness) -> crate::sandbox::SandboxInfo {
        crate::sandbox::SandboxInfo {
            name: name.into(),
            image_ref: "x".into(),
            liveness,
        }
    }

    /// A handler write that lands after the scan snapshot must survive a
    /// `replace_all` built from that (now-stale) scan.
    #[test]
    fn replace_all_keeps_entry_mutated_after_snapshot() {
        let r = Registry::new();
        r.set("web", "x", Liveness::Stopped);
        let snap = r.snapshot();
        r.set_liveness("web", Liveness::Running);
        r.replace_all(snap, vec![info("web", Liveness::Stopped)]);
        assert_eq!(r.liveness("web"), Some(Liveness::Running));
    }

    /// No writes landed after the snapshot: a normal refresh still applies.
    #[test]
    fn replace_all_applies_stale_free_updates() {
        let r = Registry::new();
        r.set("web", "x", Liveness::Running);
        let snap = r.snapshot();
        r.replace_all(snap, vec![info("web", Liveness::Stopped)]);
        assert_eq!(r.liveness("web"), Some(Liveness::Stopped));
    }

    /// A `remove` before the scan snapshot was taken must not be undone by
    /// stale scan data that still lists the sandbox.
    #[test]
    fn replace_all_does_not_resurrect_removed() {
        let r = Registry::new();
        r.set("web", "x", Liveness::Running);
        let snap = r.snapshot();
        r.remove("web");
        r.replace_all(snap, vec![info("web", Liveness::Running)]);
        assert_eq!(r.liveness("web"), None);
        assert!(r.summaries().is_empty());
    }

    /// A `set` after the snapshot for a name absent from the (now-stale)
    /// scan result must not be dropped.
    #[test]
    fn replace_all_keeps_entry_created_after_snapshot() {
        let r = Registry::new();
        let snap = r.snapshot();
        r.set("new", "x", Liveness::Stopped);
        r.replace_all(snap, vec![]);
        assert_eq!(r.liveness("new"), Some(Liveness::Stopped));
    }

    /// The guard only shields a stale scan for one cycle — a fresh scan
    /// (new snapshot taken after the mutation) applies normally.
    #[test]
    fn replace_all_converges_on_next_tick() {
        let r = Registry::new();
        r.set("web", "x", Liveness::Stopped);
        let stale_snap = r.snapshot();
        r.set_liveness("web", Liveness::Running);
        r.replace_all(stale_snap, vec![info("web", Liveness::Stopped)]);
        assert_eq!(r.liveness("web"), Some(Liveness::Running));

        // A fresh tick, scanning after the mutation, converges normally.
        let fresh_snap = r.snapshot();
        r.replace_all(fresh_snap, vec![info("web", Liveness::Stopped)]);
        assert_eq!(r.liveness("web"), Some(Liveness::Stopped));
    }

    /// Precedence: an entry present in `entries` with `mutated > snapshot`
    /// is kept regardless of any tombstone, even an older one. A `set`
    /// after a `remove` clears the tombstone's shadow for later scans, so a
    /// re-created sandbox is never dropped by a scan that predates the
    /// removal.
    #[test]
    fn set_after_remove_clears_tombstone() {
        let r = Registry::new();
        r.set("web", "x", Liveness::Running);
        r.remove("web");
        let snap = r.snapshot();
        r.set("web", "x", Liveness::Stopped);
        r.replace_all(snap, vec![info("web", Liveness::Running)]);
        assert_eq!(r.liveness("web"), Some(Liveness::Stopped));
    }
}
