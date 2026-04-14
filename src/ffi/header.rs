//! C header reference for the prime-net-engine FFI surface.
//!
//! This file is **not** consumed by the Rust compiler for code generation.
//! It serves as a human-readable reference that documents every public
//! FFI type and function so C/C++ consumers can write compatible declarations
//! without running cbindgen.
//!
//! # Opaque handles
//!
//! ```c
//! typedef struct PrimeEngine PrimeEngine;
//! typedef struct PrimeRequestHandle PrimeRequestHandle;
//! ```
//!
//! # Enums
//!
//! ```c
//! typedef enum {
//!     PRIME_REQUEST_PENDING   = 0,
//!     PRIME_REQUEST_RUNNING   = 1,
//!     PRIME_REQUEST_COMPLETED = 2,
//!     PRIME_REQUEST_CANCELLED = 3,
//!     PRIME_REQUEST_FAILED    = 4,
//! } PrimeRequestStatus;
//!
//! typedef enum {
//!     PRIME_EVENT_CONNECTION_ESTABLISHED = 1,
//!     PRIME_EVENT_CONNECTION_CLOSED      = 2,
//!     PRIME_EVENT_ROUTE_SELECTED         = 3,
//!     PRIME_EVENT_DPI_BYPASS_APPLIED     = 4,
//!     PRIME_EVENT_AD_BLOCKED             = 5,
//!     PRIME_EVENT_TRACKER_BLOCKED        = 6,
//!     PRIME_EVENT_DNS_QUERY              = 7,
//!     PRIME_EVENT_ERROR                  = 8,
//!     PRIME_EVENT_CONFIG_CHANGED         = 9,
//! } PrimeEventType;
//! ```
//!
//! # Structs
//!
//! ```c
//! typedef struct {
//!     const char  *url;
//!     const char  *method;
//!     const char **headers;
//!     size_t       headers_count;
//!     const uint8_t *body;
//!     size_t       body_len;
//! } PrimeRequest;
//!
//! typedef struct {
//!     uint16_t     status_code;
//!     const char **headers;
//!     size_t       headers_count;
//!     const uint8_t *body;
//!     size_t       body_len;
//!     int32_t      error_code;
//!     const char  *error_message;
//!     void        *owner;        /* internal -- do not touch */
//! } PrimeResponse;
//!
//! typedef struct {
//!     uint32_t active_connections;
//!     uint64_t total_connections;
//!     uint64_t bytes_sent;
//!     uint64_t bytes_received;
//!     uint64_t blocked_requests;
//!     uint64_t blocked_ads;
//!     uint64_t blocked_trackers;
//!     uint64_t dpi_bypassed;
//!     uint64_t vpn_fallback;
//!     uint64_t dns_queries;
//!     uint64_t uptime_secs;
//! } PrimeMetrics;
//!
//! typedef struct {
//!     uint64_t session_blocked;
//!     uint64_t total_blocked;
//! } PrimePrivacyStats;
//!
//! typedef struct {
//!     PrimeEventType event_type;
//!     uint64_t       timestamp_ms;
//!     const char    *message;    /* nullable */
//!     const char    *domain;     /* nullable */
//!     const char    *extra;      /* nullable */
//! } PrimeEvent;
//! ```
//!
//! # Callback types
//!
//! ```c
//! typedef void (*PrimeProgressCallback)(
//!     uint64_t downloaded,
//!     uint64_t total,
//!     double   speed_mbps,
//!     void    *user_data
//! );
//!
//! typedef void (*PrimeEventCallback)(
//!     const PrimeEvent *event,
//!     void             *user_data
//! );
//! ```
//!
//! # Engine lifecycle
//!
//! ```c
//! PrimeEngine *prime_engine_new(const char *config_path);
//! void         prime_engine_free(PrimeEngine *engine);
//! const char  *prime_last_error_message(void);
//! ```
//!
//! # Synchronous HTTP
//!
//! ```c
//! PrimeResponse *prime_engine_fetch(
//!     PrimeEngine         *engine,
//!     const PrimeRequest  *request,
//!     PrimeProgressCallback callback,
//!     void                *user_data
//! );
//! void prime_response_free(PrimeResponse *response);
//! ```
//!
//! # Asynchronous HTTP
//!
//! ```c
//! PrimeRequestHandle *prime_engine_fetch_async(
//!     PrimeEngine         *engine,
//!     const PrimeRequest  *request,
//!     PrimeProgressCallback callback,
//!     void                *user_data
//! );
//! PrimeResponse      *prime_request_wait(PrimeRequestHandle *handle, uint64_t timeout_ms);
//! int32_t             prime_request_cancel(PrimeRequestHandle *handle);
//! PrimeRequestStatus  prime_request_status(PrimeRequestHandle *handle);
//! void                prime_request_free(PrimeRequestHandle *handle);
//! ```
//!
//! # SOCKS5 control
//!
//! ```c
//! int32_t      prime_socks5_start(PrimeEngine *engine, const char *bind_addr);
//! int32_t      prime_socks5_stop(PrimeEngine *engine);
//! int32_t      prime_socks5_status(PrimeEngine *engine);
//! const char  *prime_socks5_bound_addr(PrimeEngine *engine);
//! ```
//!
//! # Configuration
//!
//! ```c
//! int32_t  prime_config_load(PrimeEngine *engine, const char *path);
//! int32_t  prime_config_load_toml(PrimeEngine *engine, const char *toml_str);
//! char    *prime_config_get_toml(PrimeEngine *engine);  /* caller frees */
//! int32_t  prime_config_set(PrimeEngine *engine, const char *key, const char *value);
//! void     prime_string_free(char *ptr);
//! ```
//!
//! # Metrics
//!
//! ```c
//! int32_t prime_metrics_get(PrimeEngine *engine, PrimeMetrics *out);
//! int32_t prime_privacy_stats(PrimeEngine *engine, PrimePrivacyStats *out);
//! ```
//!
//! # Events
//!
//! ```c
//! int32_t prime_set_event_callback(
//!     PrimeEngine       *engine,
//!     PrimeEventCallback callback,  /* NULL to unregister */
//!     void              *user_data
//! );
//! ```
//!
//! # Error codes
//!
//! | Code | Name                      |
//! |------|---------------------------|
//! | 0    | `PRIME_OK`                |
//! | 1    | `PRIME_ERR_NULL_PTR`      |
//! | 2    | `PRIME_ERR_INVALID_UTF8`  |
//! | 3    | `PRIME_ERR_INVALID_REQUEST` |
//! | 4    | `PRIME_ERR_RUNTIME`       |
