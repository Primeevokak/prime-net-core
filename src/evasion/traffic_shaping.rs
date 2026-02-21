use std::ops::Range;
use std::time::Duration;

use rand::Rng;

#[derive(Debug, Clone)]
pub struct TrafficShaper {
    pub packet_sizes: Vec<usize>,
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

    pub async fn shape_request(&self, data: &[u8]) -> Vec<Vec<u8>> {
        let chunks = self.split_with_random_sizes(data);
        for _ in &chunks {
            let delay = rand::thread_rng().gen_range(self.timing_jitter_ms.clone());
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
        chunks
    }
}
