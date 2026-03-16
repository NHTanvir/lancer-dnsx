//! Phase 8: Hybrid dedup map.
//!
//! Combines an in-memory [`dashmap::DashSet`] with an optional on-disk
//! [`redb`] spill table. The disk spill is only initialized when the
//! in-memory set grows beyond `spill_threshold`. After that point new
//! inserts are written through to both the in-memory cache and the disk
//! table, while lookups still consult the in-memory side first (fast path)
//! and only fall back to redb on a miss.
//!
//! The disk store uses a single redb table keyed by host. The value is a
//! single byte (`1`) since we only care about set semantics; redb tables
//! must have a value type so we cannot store a zero-size value.
//!
//! NOTE: Background flushing is intentionally synchronous-per-insert past
//! the spill threshold. A future revision could batch writes via a
//! background task, but the simpler "write-through above threshold" model
//! keeps the surface area small and correctness obvious.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use anyhow::{Context, Result};
use dashmap::DashSet;
use redb::{Database, TableDefinition};

const TABLE: TableDefinition<&str, u8> = TableDefinition::new("dedup");

/// Hybrid in-memory + on-disk dedup set.
pub struct HybridMap {
    mem: DashSet<String>,
    spill_threshold: usize,
    spilled: AtomicBool,
    db: Mutex<Option<Database>>,
    db_path: PathBuf,
}

impl HybridMap {
    /// Construct a new hybrid map. `db_path` is the path that will be used
    /// for the redb spill file if/when the threshold is exceeded. The file
    /// is not created until that point.
    pub fn new(spill_threshold: usize, db_path: impl AsRef<Path>) -> Self {
        Self {
            mem: DashSet::new(),
            spill_threshold,
            spilled: AtomicBool::new(false),
            db: Mutex::new(None),
            db_path: db_path.as_ref().to_path_buf(),
        }
    }

    /// Insert `host`. Returns `true` if newly inserted, `false` if it was
    /// already present (in memory or on disk).
    pub fn insert(&self, host: &str) -> bool {
        // Fast path: already known in memory.
        if self.mem.contains(host) {
            return false;
        }

        // Disk check (only if we've ever spilled).
        if self.spilled.load(Ordering::Acquire) && self.contains_on_disk(host).unwrap_or(false) {
            return false;
        }

        // Insert into memory.
        let inserted = self.mem.insert(host.to_string());
        if !inserted {
            return false;
        }

        // Decide whether to spill / write-through.
        if self.mem.len() > self.spill_threshold {
            // Initialize the db lazily.
            if !self.spilled.load(Ordering::Acquire) {
                if let Err(e) = self.init_db() {
                    eprintln!("[WARN] hybrid_map: failed to initialize disk spill: {e}");
                    return true;
                }
                self.spilled.store(true, Ordering::Release);
            }
            if let Err(e) = self.write_to_disk(host) {
                eprintln!("[WARN] hybrid_map: failed to persist {host}: {e}");
            }
        }

        true
    }

    /// Check membership.
    #[allow(dead_code)]
    pub fn contains(&self, host: &str) -> bool {
        if self.mem.contains(host) {
            return true;
        }
        if self.spilled.load(Ordering::Acquire) {
            return self.contains_on_disk(host).unwrap_or(false);
        }
        false
    }

    /// Current in-memory entry count. Disk-only entries are not counted.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.mem.len()
    }

    /// True when no entries have been inserted in this run (in-memory only;
    /// see `has_spilled` for the disk-spill status).
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.mem.is_empty()
    }

    /// True if the disk spill file has been initialized.
    #[allow(dead_code)]
    pub fn has_spilled(&self) -> bool {
        self.spilled.load(Ordering::Acquire)
    }

    fn init_db(&self) -> Result<()> {
        let mut guard = self.db.lock().expect("hybrid_map db mutex");
        if guard.is_some() {
            return Ok(());
        }
        let db = Database::create(&self.db_path)
            .with_context(|| format!("create redb database at {:?}", self.db_path))?;
        // Initialize the table.
        let tx = db.begin_write()?;
        {
            let _ = tx.open_table(TABLE)?;
        }
        tx.commit()?;
        *guard = Some(db);
        Ok(())
    }

    fn write_to_disk(&self, host: &str) -> Result<()> {
        let guard = self.db.lock().expect("hybrid_map db mutex");
        let db = guard.as_ref().context("redb not initialized")?;
        let tx = db.begin_write()?;
        {
            let mut table = tx.open_table(TABLE)?;
            table.insert(host, 1u8)?;
        }
        tx.commit()?;
        Ok(())
    }

    fn contains_on_disk(&self, host: &str) -> Result<bool> {
        let guard = self.db.lock().expect("hybrid_map db mutex");
        let Some(db) = guard.as_ref() else {
            return Ok(false);
        };
        let tx = db.begin_read()?;
        let table = match tx.open_table(TABLE) {
            Ok(t) => t,
            Err(_) => return Ok(false),
        };
        Ok(table.get(host)?.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_dedup() {
        let tmp = std::env::temp_dir().join(format!("hybrid_map_test_{}.redb", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        let m = HybridMap::new(1_000_000, &tmp);
        assert!(m.insert("a"));
        assert!(!m.insert("a"));
        assert!(m.insert("b"));
        assert_eq!(m.len(), 2);
        assert!(!m.has_spilled());
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn spill_to_disk() {
        let tmp =
            std::env::temp_dir().join(format!("hybrid_map_spill_{}.redb", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        let m = HybridMap::new(2, &tmp);
        assert!(m.insert("a"));
        assert!(m.insert("b"));
        assert!(m.insert("c")); // crosses threshold (mem.len() > 2)
        assert!(m.has_spilled());
        assert!(m.contains("c"));
        assert!(!m.insert("c"));
        let _ = std::fs::remove_file(&tmp);
    }
}
