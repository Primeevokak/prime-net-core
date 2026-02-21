use std::ffi::c_void;

pub type ProgressCallback =
    Option<extern "C" fn(downloaded: u64, total: u64, speed_mbps: f64, user_data: *mut c_void)>;

#[derive(Clone, Copy)]
pub struct FfiProgressContext {
    pub callback: ProgressCallback,
    pub user_data_bits: usize,
}

impl FfiProgressContext {
    pub fn emit(&self, downloaded: u64, total: u64, speed_mbps: f64) {
        if let Some(cb) = self.callback {
            cb(
                downloaded,
                total,
                speed_mbps,
                self.user_data_bits as *mut c_void,
            );
        }
    }
}
