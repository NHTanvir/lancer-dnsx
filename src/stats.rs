//! Phase 8: live stats counters with an optional progress bar.
//!
//! `Stats` is cheap to clone via `Arc` and safe to call from every worker.
//! When the progress bar is enabled (`with_bar`), counter increments also
//! tick the bar; otherwise counters are pure atomic ops.

use std::sync::atomic::{AtomicU64, Ordering};

use indicatif::{ProgressBar, ProgressStyle};

pub(crate) struct Stats {
    total: AtomicU64,
    resolved: AtomicU64,
    errors: AtomicU64,
    dropped: AtomicU64,
    bar: Option<ProgressBar>,
}

impl Stats {
    /// Construct a counter-only `Stats` instance with no progress bar.
    pub(crate) fn new() -> Self {
        Self {
            total: AtomicU64::new(0),
            resolved: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            bar: None,
        }
    }

    /// Construct a `Stats` with a configured `indicatif` progress bar.
    /// `total_hosts` is shown as the bar's `len`. Output goes to stderr
    /// (the indicatif default).
    pub(crate) fn with_bar(total_hosts: u64) -> Self {
        let bar = ProgressBar::new(total_hosts);
        let style = ProgressStyle::with_template(
            "[{elapsed_precise}] {bar:40} {pos}/{len} ({per_sec}) | errors: {msg}",
        )
        .unwrap_or_else(|_| ProgressStyle::default_bar());
        bar.set_style(style);
        bar.set_message("0");
        Self {
            total: AtomicU64::new(0),
            resolved: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            bar: Some(bar),
        }
    }

    /// Mark one host as resolved.
    pub(crate) fn inc_resolved(&self) {
        self.resolved.fetch_add(1, Ordering::Relaxed);
        self.tick();
    }

    /// Mark one host as errored.
    pub(crate) fn inc_error(&self) {
        let n = self.errors.fetch_add(1, Ordering::Relaxed) + 1;
        if let Some(bar) = &self.bar {
            bar.set_message(n.to_string());
        }
        self.tick();
    }

    /// Mark one host as dropped (filtered out, wildcard, etc.).
    pub(crate) fn inc_dropped(&self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
        self.tick();
    }

    fn tick(&self) {
        self.total.fetch_add(1, Ordering::Relaxed);
        if let Some(bar) = &self.bar {
            bar.inc(1);
        }
    }

    /// Finalize the progress bar (if present) and print a one-line summary
    /// on stderr.
    pub(crate) fn finish(&self) {
        if let Some(bar) = &self.bar {
            bar.finish_and_clear();
        }
        eprintln!(
            "[STATS] total={} resolved={} errors={} dropped={}",
            self.total.load(Ordering::Relaxed),
            self.resolved.load(Ordering::Relaxed),
            self.errors.load(Ordering::Relaxed),
            self.dropped.load(Ordering::Relaxed),
        );
    }
}
