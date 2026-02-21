use std::collections::VecDeque;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;
use regex::Regex;
use tracing::Level;

use crate::error::Result;

#[derive(Debug)]
pub struct LogViewer {
    pub logs: Arc<RwLock<VecDeque<LogEntry>>>,
    filtered_cache: Mutex<Option<Vec<LogEntry>>>,
    cache_dirty: AtomicBool,
    filter_level: RwLock<Option<Level>>,
    category_filter: RwLock<Option<String>>,
    search_query: RwLock<String>,
    use_regex: AtomicBool,
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

impl LogViewer {
    pub fn new() -> Self {
        Self {
            logs: Arc::new(RwLock::new(VecDeque::with_capacity(10_000))),
            filtered_cache: Mutex::new(None),
            cache_dirty: AtomicBool::new(true),
            filter_level: RwLock::new(None),
            category_filter: RwLock::new(None),
            search_query: RwLock::new(String::new()),
            use_regex: AtomicBool::new(false),
            auto_scroll: AtomicBool::new(true),
            selected_line: AtomicUsize::new(0),
        }
    }

    pub fn add_log(&self, entry: LogEntry) {
        let mut logs = self.logs.write();
        if logs.len() >= 10_000 {
            logs.pop_front();
        }
        logs.push_back(entry);
        self.cache_dirty.store(true, Ordering::Relaxed);
    }

    pub fn clear(&self) {
        self.logs.write().clear();
        self.cache_dirty.store(true, Ordering::Relaxed);
        self.selected_line.store(0, Ordering::Relaxed);
    }

    pub fn filtered_logs(&self) -> Vec<LogEntry> {
        if !self.cache_dirty.load(Ordering::Relaxed) {
            let cache = self.cache_guard();
            if let Some(cached) = cache.as_ref() {
                return cached.clone();
            }
        }

        let logs = self.logs.read();
        let filter_level = *self.filter_level.read();
        let category_filter = self.category_filter.read().clone();
        let search_query = self.search_query.read().clone();
        let use_regex = self.use_regex.load(Ordering::Relaxed);
        let regex = if use_regex && !search_query.is_empty() {
            Regex::new(&search_query).ok()
        } else {
            None
        };

        let filtered = logs
            .iter()
            .filter(|entry| {
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
                if let Some(re) = regex.as_ref() {
                    re.is_match(&entry.message) || re.is_match(&entry.target)
                } else {
                    entry.message.contains(&search_query) || entry.target.contains(&search_query)
                }
            })
            .cloned()
            .collect::<Vec<_>>();

        let mut cache = self.cache_guard();
        *cache = Some(filtered.clone());
        self.cache_dirty.store(false, Ordering::Relaxed);

        filtered
    }

    pub fn visible_logs(&self, max_lines: usize) -> Vec<LogEntry> {
        let all = self.filtered_logs();
        if all.is_empty() || max_lines == 0 {
            return Vec::new();
        }

        let auto_scroll = self.auto_scroll.load(Ordering::Relaxed);
        let selected_line = self.selected_line.load(Ordering::Relaxed);
        if auto_scroll || selected_line == 0 {
            let skip = all.len().saturating_sub(max_lines);
            all[skip..].to_vec()
        } else {
            let start = selected_line.min(all.len().saturating_sub(1));
            let end = (start + max_lines).min(all.len());
            all[start..end].to_vec()
        }
    }

    pub fn set_filter_level(&self, filter_level: Option<Level>) {
        let mut current = self.filter_level.write();
        if *current != filter_level {
            *current = filter_level;
            self.cache_dirty.store(true, Ordering::Relaxed);
        }
    }

    pub fn filter_level(&self) -> Option<Level> {
        *self.filter_level.read()
    }

    pub fn set_category_filter(&self, category: Option<String>) {
        let mut current = self.category_filter.write();
        if *current != category {
            *current = category;
            self.cache_dirty.store(true, Ordering::Relaxed);
        }
    }

    pub fn category_filter(&self) -> Option<String> {
        self.category_filter.read().clone()
    }

    pub fn set_search_query(&self, query: String) {
        let mut current = self.search_query.write();
        if *current != query {
            *current = query;
            self.cache_dirty.store(true, Ordering::Relaxed);
        }
    }

    pub fn set_use_regex(&self, use_regex: bool) {
        let prev = self.use_regex.swap(use_regex, Ordering::Relaxed);
        if prev != use_regex {
            self.cache_dirty.store(true, Ordering::Relaxed);
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
        for entry in self.filtered_logs() {
            let ts = format_timestamp(entry.timestamp);
            writeln!(
                file,
                "{} {:5} {:<24} {}",
                ts, entry.level, entry.target, entry.message
            )?;
        }
        Ok(())
    }

    fn cache_guard(&self) -> MutexGuard<'_, Option<Vec<LogEntry>>> {
        match self.filtered_cache.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
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
