use rand::Rng;

#[derive(Debug, Clone, Copy)]
pub enum BypassMethod {
    HttpFragmentation,
    TcpSegmentation,
    PacketReordering,
    TtlManipulation,
    FakeSni,
}

#[derive(Debug, Clone)]
pub struct DpiBypass {
    pub methods: Vec<BypassMethod>,
}

impl Default for DpiBypass {
    fn default() -> Self {
        Self {
            methods: vec![BypassMethod::HttpFragmentation],
        }
    }
}

impl DpiBypass {
    pub fn apply_fragmentation(&self, data: &[u8]) -> Vec<Vec<u8>> {
        if data.is_empty() {
            return Vec::new();
        }
        let fragment_size = rand::thread_rng().gen_range(2..8);
        data.chunks(fragment_size).map(|c| c.to_vec()).collect()
    }
}
