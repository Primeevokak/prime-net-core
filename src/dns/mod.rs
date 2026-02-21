//! DNS resolver implementation and configuration.
//!
//! This module provides a "universal" DNS resolver with multiple upstream types (system DNS, DoH, DoT, DoQ).
//! When compiled with the `hickory-dns` feature, upstream resolvers are built using Hickory Resolver.
pub mod resolver;

pub use resolver::{
    DnsConfig, DnsResolverType, DnsResponse, DnsTlsUpstream, DoHProvider, MxRecord, SrvRecord,
    UniversalDnsResolver,
};
