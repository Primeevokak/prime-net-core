// Semantically grouped sections for SOCKS5 PT server.
include!("socks5_server_parts/state_and_startup.rs");
include!("socks5_server_parts/route_connection.rs");
include!("socks5_server_parts/protocol_handlers.rs");
include!("socks5_server_parts/route_scoring.rs");
include!("socks5_server_parts/classifier_and_persistence.rs");
include!("socks5_server_parts/relay_and_io_helpers.rs");
include!("socks5_server_parts/tests.rs");
