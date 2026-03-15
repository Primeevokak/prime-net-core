//! Platform-agnostic TCP disorder handle.
//!
//! A [`TcpDisorderHandle`] is returned by [`PacketInterceptor::intercept_connection`]
//! and represents an active intercept session for one TCP connection.  Dropping it
//! cancels the intercept and releases kernel resources.

use std::sync::Arc;
use tokio::sync::oneshot;

/// Active packet-intercept session for a single TCP connection.
///
/// The handle drives the disorder logic:
/// - The backend intercepts the first outgoing data segment (segment 1) and
///   holds it.
/// - It immediately forwards segment 2.
/// - After `delay_ms` milliseconds it sends segment 1.
///
/// Drop the handle (or call [`cancel`]) after the TLS handshake completes to
/// free kernel filter resources.
///
/// [`cancel`]: TcpDisorderHandle::cancel
#[derive(Debug)]
pub struct TcpDisorderHandle {
    cancel_tx: Option<oneshot::Sender<()>>,
    _backend_ref: Arc<dyn super::PacketInterceptor>,
}

impl TcpDisorderHandle {
    /// Build a handle.  `cancel_tx` signals the backend's intercept task to stop.
    pub(super) fn new(
        cancel_tx: oneshot::Sender<()>,
        backend: Arc<dyn super::PacketInterceptor>,
    ) -> Self {
        Self {
            cancel_tx: Some(cancel_tx),
            _backend_ref: backend,
        }
    }

    /// Explicitly cancel the intercept before the handle is dropped.
    pub fn cancel(mut self) {
        if let Some(tx) = self.cancel_tx.take() {
            let _ = tx.send(());
        }
    }
}

impl Drop for TcpDisorderHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.cancel_tx.take() {
            let _ = tx.send(());
        }
    }
}
