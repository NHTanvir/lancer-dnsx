//! Phase 8: resume state persisted to `resume.cfg`.
//!
//! On startup we load the JSON (if present) and treat every host inside
//! as already done. Workers call [`ResumeState::mark_done`] after each
//! host completes; every 100 marks the file is rewritten atomically
//! (`resume.cfg.tmp` then `rename`). The same flush also runs from the
//! Ctrl-C handler and at the end of a normal run.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

const SAVE_EVERY: u64 = 100;
pub const DEFAULT_FILENAME: &str = "resume.cfg";

#[derive(Serialize, Deserialize, Default)]
struct ResumeFile {
    completed: Vec<String>,
}

pub struct ResumeState {
    path: PathBuf,
    completed: Mutex<HashSet<String>>,
    marks_since_save: AtomicU64,
}

impl ResumeState {
    /// Load a `ResumeState` from `path`. Missing files are not an error —
    /// they produce an empty state. Malformed files surface as an error.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let completed: HashSet<String> = if path.exists() {
            let data = std::fs::read_to_string(&path)
                .with_context(|| format!("read {}", path.display()))?;
            let file: ResumeFile = serde_json::from_str(&data)
                .with_context(|| format!("parse {}", path.display()))?;
            file.completed.into_iter().collect()
        } else {
            HashSet::new()
        };
        Ok(Self {
            path,
            completed: Mutex::new(completed),
            marks_since_save: AtomicU64::new(0),
        })
    }

    /// Returns true if `host` is in the completed set (i.e. should be skipped).
    pub fn is_done(&self, host: &str) -> bool {
        let guard = self.completed.lock().expect("resume mutex");
        guard.contains(host)
    }

    /// Number of already-completed hosts (informational).
    pub fn done_count(&self) -> usize {
        self.completed.lock().expect("resume mutex").len()
    }

    /// Mark a host as done. Every `SAVE_EVERY` calls the state is flushed.
    /// Flush errors are logged but not surfaced (we don't want resume
    /// bookkeeping to abort a real run).
    pub fn mark_done(&self, host: &str) {
        {
            let mut guard = self.completed.lock().expect("resume mutex");
            guard.insert(host.to_string());
        }
        let n = self.marks_since_save.fetch_add(1, Ordering::Relaxed) + 1;
        if n.is_multiple_of(SAVE_EVERY) {
            if let Err(e) = self.save() {
                eprintln!("[WARN] resume: save failed: {e}");
            }
        }
    }

    /// Write `resume.cfg` atomically.
    pub fn save(&self) -> Result<()> {
        let snapshot: Vec<String> = {
            let guard = self.completed.lock().expect("resume mutex");
            guard.iter().cloned().collect()
        };
        let file = ResumeFile {
            completed: snapshot,
        };
        let json = serde_json::to_string(&file).context("serialize resume state")?;
        let tmp = self.path.with_extension("cfg.tmp");
        std::fs::write(&tmp, json).with_context(|| format!("write {}", tmp.display()))?;
        // On Windows `rename` fails if the target exists -- remove it first.
        if self.path.exists() {
            let _ = std::fs::remove_file(&self.path);
        }
        std::fs::rename(&tmp, &self.path)
            .with_context(|| format!("rename {} -> {}", tmp.display(), self.path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let tmp = std::env::temp_dir().join(format!("resume_test_{}.cfg", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        let state = ResumeState::load(&tmp).unwrap();
        assert_eq!(state.done_count(), 0);
        state.mark_done("a.example.com");
        state.mark_done("b.example.com");
        state.save().unwrap();
        let state2 = ResumeState::load(&tmp).unwrap();
        assert_eq!(state2.done_count(), 2);
        assert!(state2.is_done("a.example.com"));
        assert!(!state2.is_done("c.example.com"));
        let _ = std::fs::remove_file(&tmp);
    }
}
