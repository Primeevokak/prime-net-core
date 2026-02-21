use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ConnectionPoolConfig {
    pub max_idle_per_host: usize,
    pub idle_timeout_secs: u64,
}

impl Default for ConnectionPoolConfig {
    fn default() -> Self {
        Self {
            max_idle_per_host: 16,
            idle_timeout_secs: 30,
        }
    }
}

impl ConnectionPoolConfig {
    pub fn apply(&self, builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
        builder
            .pool_max_idle_per_host(self.max_idle_per_host)
            .pool_idle_timeout(Duration::from_secs(self.idle_timeout_secs))
    }
}
