//! In-memory store for SSH credentials of queued deep scans.
//!
//! Secrets are never written to the DB, logs or audit trail. The worker `take`s them when it
//! claims the scan, so an entry never outlives the scan; a server restart simply drops them
//! (`db::fail_interrupted` then fails the orphaned queued scans).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use vs_core::SshCreds;

#[derive(Clone, Default)]
pub struct CredStore(Arc<Mutex<HashMap<String, SshCreds>>>);

impl CredStore {
    fn map(&self) -> MutexGuard<'_, HashMap<String, SshCreds>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn put(&self, scan_id: &str, creds: SshCreds) {
        self.map().insert(scan_id.to_string(), creds);
    }

    /// Remove and return the credentials (also used to discard them).
    pub fn take(&self, scan_id: &str) -> Option<SshCreds> {
        self.map().remove(scan_id)
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.map().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_removes_the_entry() {
        let s = CredStore::default();
        let c = SshCreds::password("u", 22, "pw").unwrap();
        s.put("a", c);
        assert_eq!(s.len(), 1);
        assert!(s.take("a").is_some());
        assert!(s.take("a").is_none());
        assert_eq!(s.len(), 0);
    }
}
