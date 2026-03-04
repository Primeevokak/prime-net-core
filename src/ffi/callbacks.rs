use std::ffi::c_void;

pub type ProgressCallback =
    Option<extern "C" fn(downloaded: u64, total: u64, speed_mbps: f64, user_data: *mut c_void)>;

#[derive(Clone, Copy)]
pub struct FfiProgressContext {
    pub callback: ProgressCallback,
    pub user_data_bits: usize,
}

// SAFETY: FfiProgressContext is used to pass callback data to the background engine thread.
// The callback itself is an extern "C" fn (function pointer), which is Send/Sync.
// The user_data is passed as a raw pointer bits (usize). The caller of the FFI API
// must ensure that the underlying data remains valid for the duration of the request.
unsafe impl Send for FfiProgressContext {}
unsafe impl Sync for FfiProgressContext {}

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
