use std::collections::VecDeque;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;
use regex::Regex;
use tracing::Level;

use crate::error::Result;

const MAX_LOGS_SIZE_BYTES: usize = 5 * 1024 * 1024;

#[derive(Debug)]
pub struct LogViewer {
    pub logs: Arc<RwLock<VecDeque<LogEntry>>>,
    approx_size_bytes: AtomicUsize,
    filtered_storage: RwLock<Vec<LogEntry>>,
    filtered_snapshot: RwLock<Arc<Vec<LogEntry>>>,
    cache_dirty: AtomicBool,
    filter_level: RwLock<Option<Level>>,
    category_filter: RwLock<Option<String>>,
    search_query: RwLock<String>,
    use_regex: AtomicBool,
    /// Cached compiled regex — rebuilt whenever `search_query` changes.
    cached_regex: RwLock<Option<Regex>>,
    auto_scroll: AtomicBool,
    selected_line: AtomicUsize,
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: SystemTime,
    pub level: Level,
    pub message: String,
    pub target: String,
}

impl LogEntry {
    fn approx_size(&self) -> usize {
        std::mem::size_of::<Self>() + self.message.len() + self.target.len()
    }
}

impl LogViewer {
    pub fn new() -> Self {
        Self {
            logs: Arc::new(RwLock::new(VecDeque::with_capacity(10_000))),
            approx_size_bytes: AtomicUsize::new(0),
            filtered_storage: RwLock::new(Vec::with_capacity(10_000)),
            filtered_snapshot: RwLock::new(Arc::new(Vec::new())),
            cache_dirty: AtomicBool::new(true),
            filter_level: RwLock::new(None),
            category_filter: RwLock::new(None),
            search_query: RwLock::new(String::new()),
            use_regex: AtomicBool::new(false),
            cached_regex: RwLock::new(None),
            auto_scroll: AtomicBool::new(true),
            selected_line: AtomicUsize::new(0),
        }
    }

    pub fn add_log(&self, entry: LogEntry) {
        let entry_size = entry.approx_size();

        // 1. Add to the global log buffer
        let mut logs = self.logs.write();
        let mut current_size = self.approx_size_bytes.load(Ordering::Relaxed);

        let mut removed_any = false;
        while current_size + entry_size > MAX_LOGS_SIZE_BYTES && !logs.is_empty() {
            if let Some(oldest) = logs.pop_front() {
                current_size = current_size.saturating_sub(oldest.approx_size());
                removed_any = true;
            }
        }

        current_size += entry_size;
        logs.push_back(entry.clone());
        self.approx_size_bytes
            .store(current_size, Ordering::Relaxed);

        // 2. Incremental update of the filtered storage
        if !removed_any {
            if self.entry_matches_filters(&entry) {
                let mut storage = self.filtered_storage.write();
                storage.push(entry);
                self.cache_dirty.store(true, Ordering::Relaxed);
            }
        } else {
            self.cache_dirty.store(true, Ordering::Relaxed);
        }
    }

    fn entry_matches_filters(&self, entry: &LogEntry) -> bool {
        let filter_level = *self.filter_level.read();
        let category_filter = self.category_filter.read();
        let search_query = self.search_query.read();

        if let Some(level) = filter_level {
            if level_rank(entry.level) > level_rank(level) {
                return false;
            }
        }
        if let Some(tag) = category_filter.as_ref() {
            if !entry.message.contains(tag) && !entry.target.contains(tag) {
                return false;
            }
        }
        if search_query.is_empty() {
            return true;
        }

        if self.use_regex.load(Ordering::Relaxed) {
            let cached = self.cached_regex.read();
            if let Some(re) = cached.as_ref() {
                return re.is_match(&entry.message) || re.is_match(&entry.target);
            }
        }

        entry.message.contains(&*search_query) || entry.target.contains(&*search_query)
    }

    pub fn clear(&self) {
        self.logs.write().clear();
        self.approx_size_bytes.store(0, Ordering::Relaxed);
        {
            let mut storage = self.filtered_storage.write();
            storage.clear();
            let mut snapshot = self.filtered_snapshot.write();
            *snapshot = Arc::new(Vec::new());
        }
        self.cache_dirty.store(false, Ordering::Relaxed);
        self.selected_line.store(0, Ordering::Relaxed);
    }

    pub fn filtered_logs(&self) -> Arc<Vec<LogEntry>> {
        if !self.cache_dirty.load(Ordering::Relaxed) {
            return self.filtered_snapshot.read().clone();
        }

        let mut snapshot = self.filtered_snapshot.write();
        // Check dirty again after acquiring the write lock
        if !self.cache_dirty.load(Ordering::Relaxed) {
            return snapshot.clone();
        }

        let logs = self.logs.read();
        let mut storage = self.filtered_storage.write();

        // Full re-filter if storage state is suspicious
        if storage.is_empty() && !logs.is_empty() || storage.len() > logs.len() {
            let filtered = logs
                .iter()
                .filter(|entry| self.entry_matches_filters(entry))
                .cloned()
                .collect::<Vec<_>>();
            *storage = filtered;
        }

        *snapshot = Arc::new(storage.clone());
        self.cache_dirty.store(false, Ordering::Relaxed);

        snapshot.clone()
    }

    pub fn visible_logs(&self, max_lines: usize) -> Vec<LogEntry> {
        let all = self.filtered_logs();
        if all.is_empty() || max_lines == 0 {
            return Vec::new();
        }

        let auto_scroll = self.auto_scroll.load(Ordering::Relaxed);
        let selected_line = self.selected_line.load(Ordering::Relaxed);
        if auto_scroll {
            let skip = all.len().saturating_sub(max_lines);
            all[skip..].to_vec()
        } else {
            let start = selected_line.min(all.len().saturating_sub(1));
            let end = (start + max_lines).min(all.len());
            all[start..end].to_vec()
        }
    }

    /// Clears the incremental filter cache and marks it dirty so the next
    /// [`filtered_logs`] call performs a full re-filter from `logs`.
    fn invalidate_filter_cache(&self) {
        self.filtered_storage.write().clear();
        self.cache_dirty.store(true, Ordering::Relaxed);
    }

    pub fn set_filter_level(&self, filter_level: Option<Level>) {
        let mut current = self.filter_level.write();
        if *current != filter_level {
            *current = filter_level;
            drop(current);
            self.invalidate_filter_cache();
        }
    }

    pub fn filter_level(&self) -> Option<Level> {
        *self.filter_level.read()
    }

    pub fn set_category_filter(&self, category: Option<String>) {
        let mut current = self.category_filter.write();
        if *current != category {
            *current = category;
            drop(current);
            self.invalidate_filter_cache();
        }
    }

    pub fn category_filter(&self) -> Option<String> {
        self.category_filter.read().clone()
    }

    pub fn set_search_query(&self, query: String) {
        let mut current = self.search_query.write();
        if *current != query {
            // Recompile the cached regex whenever the query changes
            *self.cached_regex.write() = if query.is_empty() {
                None
            } else {
                Regex::new(&query).ok()
            };
            *current = query;
            self.invalidate_filter_cache();
        }
    }

    pub fn set_use_regex(&self, use_regex: bool) {
        let prev = self.use_regex.swap(use_regex, Ordering::Relaxed);
        if prev != use_regex {
            self.invalidate_filter_cache();
        }
    }

    pub fn use_regex(&self) -> bool {
        self.use_regex.load(Ordering::Relaxed)
    }

    pub fn set_auto_scroll(&self, auto_scroll: bool) {
        self.auto_scroll.store(auto_scroll, Ordering::Relaxed);
    }

    pub fn auto_scroll(&self) -> bool {
        self.auto_scroll.load(Ordering::Relaxed)
    }

    pub fn selected_line(&self) -> usize {
        self.selected_line.load(Ordering::Relaxed)
    }

    pub fn scroll_down(&self) {
        self.auto_scroll.store(false, Ordering::Relaxed);
        let total = self.filtered_logs().len();
        let current = self.selected_line.load(Ordering::Relaxed);
        if current + 1 < total {
            self.selected_line.store(current + 1, Ordering::Relaxed);
        }
    }

    pub fn scroll_up(&self) {
        self.auto_scroll.store(false, Ordering::Relaxed);
        let current = self.selected_line.load(Ordering::Relaxed);
        if current > 0 {
            self.selected_line.store(current - 1, Ordering::Relaxed);
        }
    }

    pub fn jump_to_bottom(&self) {
        self.auto_scroll.store(true, Ordering::Relaxed);
        let total = self.filtered_logs().len();
        self.selected_line
            .store(total.saturating_sub(1), Ordering::Relaxed);
    }

    pub fn export_to_file(&self, path: &Path) -> Result<()> {
        let mut file = File::create(path)?;

        // Dynamic system information header
        writeln!(file, "=== PRIME NET ENGINE LOG EXPORT ===")?;
        writeln!(
            file,
            "version=\"{}\" os=\"{}\" arch=\"{}\" build=\"{}\"",
            crate::version::APP_VERSION,
            std::env::consts::OS,
            std::env::consts::ARCH,
            if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            }
        )?;
        writeln!(file, "------------------------------------")?;
        writeln!(file)?;

        for entry in self.filtered_logs().iter() {
            let ts = format_timestamp(entry.timestamp);
            writeln!(
                file,
                "{} {:5} {:<24} {}",
                ts, entry.level, entry.target, entry.message
            )?;
        }
        Ok(())
    }
}

impl Default for LogViewer {
    fn default() -> Self {
        Self::new()
    }
}

pub fn format_timestamp(ts: SystemTime) -> String {
    let secs = ts
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    let rem = secs % 86_400;
    let h = rem / 3600;
    let m = (rem % 3600) / 60;
    let s = rem % 60;
    format!("{h:02}:{m:02}:{s:02}")
}

fn level_rank(level: Level) -> u8 {
    match level {
        Level::ERROR => 1,
        Level::WARN => 2,
        Level::INFO => 3,
        Level::DEBUG => 4,
        Level::TRACE => 5,
    }
}
