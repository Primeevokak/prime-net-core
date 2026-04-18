use std::ops::Range;
use std::time::Duration;

use rand::Rng;

/// Shapes outgoing traffic by splitting data into random-sized chunks
/// with inter-chunk jitter delays to defeat traffic analysis.
#[derive(Debug, Clone)]
pub struct TrafficShaper {
    /// Pool of candidate chunk sizes (one is picked randomly per split).
    pub packet_sizes: Vec<usize>,
    /// Range of inter-chunk delay in milliseconds.
    pub timing_jitter_ms: Range<u64>,
}

impl Default for TrafficShaper {
    fn default() -> Self {
        Self {
            packet_sizes: vec![256, 512, 1024, 2048, 4096],
            timing_jitter_ms: 5..35,
        }
    }
}

impl TrafficShaper {
    /// Split `data` into randomly-sized chunks.
    pub fn split_with_random_sizes(&self, data: &[u8]) -> Vec<Vec<u8>> {
        if data.is_empty() {
            return Vec::new();
        }
        let mut parts = Vec::new();
        let mut cursor = 0usize;
        while cursor < data.len() {
            let size = self
                .packet_sizes
                .get(rand::thread_rng().gen_range(0..self.packet_sizes.len()))
                .copied()
                .unwrap_or(1024);
            let end = (cursor + size).min(data.len());
            parts.push(data[cursor..end].to_vec());
            cursor = end;
        }
        parts
    }

    /// Split data into chunks and return them paired with per-chunk delays.
    ///
    /// The caller should write each chunk, then sleep for the associated delay
    /// before writing the next one.  This ensures jitter happens *between*
    /// actual network writes, not before all of them.
    pub fn shape_request(&self, data: &[u8]) -> Vec<(Vec<u8>, Duration)> {
        let chunks = self.split_with_random_sizes(data);
        chunks
            .into_iter()
            .map(|chunk| {
                let delay = if self.timing_jitter_ms.start < self.timing_jitter_ms.end {
                    rand::thread_rng().gen_range(self.timing_jitter_ms.clone())
                } else {
                    0
                };
                (chunk, Duration::from_millis(delay))
            })
            .collect()
    }
}
