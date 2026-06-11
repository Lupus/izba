//! The daemon's in-memory view of sandboxes. NOT authoritative — disk state
//! (sandbox dirs + pid identity) remains the source of truth; this is a
//! cache rebuilt at adoption and refreshed by the supervisor tick and by
//! lifecycle handlers, so `List`/`Status` answer without re-probing.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::daemon::proto::SandboxSummary;
use crate::liveness::Liveness;
use crate::sandbox::SandboxInfo;

#[derive(Debug, Clone)]
struct Entry {
    image_ref: String,
    liveness: Liveness,
}

#[derive(Default)]
pub struct Registry {
    inner: Mutex<HashMap<String, Entry>>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&self, name: &str, image_ref: &str, liveness: Liveness) {
        self.inner.lock().unwrap().insert(
            name.to_string(),
            Entry {
                image_ref: image_ref.to_string(),
                liveness,
            },
        );
    }

    /// Update liveness only; no-op for unknown names.
    pub fn set_liveness(&self, name: &str, liveness: Liveness) {
        if let Some(e) = self.inner.lock().unwrap().get_mut(name) {
            e.liveness = liveness;
        }
    }

    pub fn remove(&self, name: &str) {
        self.inner.lock().unwrap().remove(name);
    }

    pub fn liveness(&self, name: &str) -> Option<Liveness> {
        self.inner
            .lock()
            .unwrap()
            .get(name)
            .map(|e| e.liveness.clone())
    }

    /// Sandboxes with a live VMM (Running or Degraded) — drives idle-exit.
    pub fn running_count(&self) -> usize {
        self.inner
            .lock()
            .unwrap()
            .values()
            .filter(|e| e.liveness != Liveness::Stopped)
            .count()
    }

    pub fn summaries(&self) -> Vec<SandboxSummary> {
        let mut out: Vec<SandboxSummary> = self
            .inner
            .lock()
            .unwrap()
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

    /// Swap in a complete fresh view (adoption, supervisor tick).
    pub fn replace_all(&self, infos: Vec<SandboxInfo>) {
        let fresh: HashMap<String, Entry> = infos
            .into_iter()
            .map(|i| {
                (
                    i.name,
                    Entry {
                        image_ref: i.image_ref,
                        liveness: i.liveness,
                    },
                )
            })
            .collect();
        *self.inner.lock().unwrap() = fresh;
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
            Liveness::Degraded("sidecar passt died".into()),
        );

        let s = r.summaries();
        // Sorted by name.
        assert_eq!(
            s.iter().map(|x| x.name.as_str()).collect::<Vec<_>>(),
            vec!["api", "db", "web"]
        );
        assert_eq!(s[2].status, "running");
        assert_eq!(s[0].status, "degraded (sidecar passt died)");
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
    fn replace_all_swaps_the_view() {
        let r = Registry::new();
        r.set("old", "x", Liveness::Running);
        r.replace_all(vec![crate::sandbox::SandboxInfo {
            name: "new".into(),
            image_ref: "y".into(),
            liveness: Liveness::Stopped,
        }]);
        let s = r.summaries();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].name, "new");
    }
}
