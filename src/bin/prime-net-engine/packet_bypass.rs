//! Packet-level bypass — reserved module.
//!
//! The external ciadpi backend has been replaced by the in-process
//! [`TcpDesyncEngine`](prime_net_engine_core::evasion::TcpDesyncEngine).
//! All bypass routing is now handled natively inside the relay pipeline.
