//! Ad-blocking engine with EasyList/AdGuard filter syntax support.
//!
//! Provides DNS-level domain blocking, URL-level request blocking,
//! cosmetic CSS injection, and scriptlet injection.  Filter lists are
//! downloaded and cached locally with automatic updates.

pub mod config;
pub mod cosmetic;
pub mod dns_interceptor;
pub mod filter_engine;
pub mod filter_list;
pub mod filter_parser;
pub mod filter_rule;

pub use config::AdblockConfig;
pub use cosmetic::{build_cosmetic_css, CosmeticRule, ScriptletRule};
pub use dns_interceptor::DnsInterceptor;
pub use filter_engine::{ContentType, FilterEngine, FilterResult};
pub use filter_list::{
    default_filter_lists, load_cached_list, needs_update, update_all_lists, update_filter_list,
    FilterListMeta, FilterListSource,
};
pub use filter_parser::{parse_filter_list, ParseResult};
pub use filter_rule::{
    ContentTypeMask, DomainConstraint, FilterPattern, NetworkRule, RuleOptions, WildcardPattern,
};
