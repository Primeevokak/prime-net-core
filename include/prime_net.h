#ifndef PRIME_NET_H
#define PRIME_NET_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct PrimeEngine PrimeEngine;
typedef struct PrimeRequestHandle PrimeRequestHandle;

/* Result codes (also used in PrimeResponse.error_code). */
#define PRIME_OK 0
#define PRIME_ERR_NULL_PTR 1
#define PRIME_ERR_INVALID_UTF8 2
#define PRIME_ERR_INVALID_REQUEST 3
#define PRIME_ERR_RUNTIME 4

typedef int32_t PrimeResult;

typedef enum {
    PRIME_REQUEST_STATUS_PENDING = 0,
    PRIME_REQUEST_STATUS_RUNNING = 1,
    PRIME_REQUEST_STATUS_COMPLETED = 2,
    PRIME_REQUEST_STATUS_CANCELLED = 3,
    PRIME_REQUEST_STATUS_FAILED = 4
} PrimeRequestStatus;

typedef struct {
    const char* url;
    const char* method;
    const char** headers; /* "Key: Value" strings */
    size_t headers_count;
    const uint8_t* body;
    size_t body_len;
} PrimeRequest;

typedef struct {
    uint16_t status_code;
    const char** headers;
    size_t headers_count;
    const uint8_t* body;
    size_t body_len;
    int32_t error_code;            /* 0 when request succeeded */
    const char* error_message;     /* null when request succeeded */
    void* owner;                   /* internal, do not use */
} PrimeResponse;

typedef void (*ProgressCallback)(uint64_t downloaded, uint64_t total, double speed_mbps, void* user_data);

/* Creates engine from config file path; pass NULL to use defaults. */
PrimeEngine* prime_engine_new(const char* config_path);
void prime_engine_free(PrimeEngine* engine);

PrimeResponse* prime_engine_fetch(
    PrimeEngine* engine,
    const PrimeRequest* request,
    ProgressCallback callback,
    void* user_data
);

/* Enqueues request for parallel execution and returns an opaque handle. Returns NULL on failure. */
PrimeRequestHandle* prime_engine_fetch_async(
    PrimeEngine* engine,
    const PrimeRequest* request,
    ProgressCallback callback,
    void* user_data
);

/*
 * Blocks the calling thread until the request is done or timeout expires.
 * timeout_ms = 0 means wait indefinitely.
 * On terminal completion (success or failure), the handle is automatically freed and a PrimeResponse is returned.
 * On timeout, the handle remains valid and can be waited on again.
 */
PrimeResponse* prime_request_wait(PrimeRequestHandle* handle, uint64_t timeout_ms);

/* Best-effort cancellation: aborts the underlying network task and updates status. */
PrimeResult prime_request_cancel(PrimeRequestHandle* handle);

/* Returns the current request status (best-effort; may lag slightly under load). */
PrimeRequestStatus prime_request_status(PrimeRequestHandle* handle);

/* Frees a request handle without waiting (best-effort: also cancels the underlying request). */
void prime_request_free(PrimeRequestHandle* handle);

void prime_response_free(PrimeResponse* response);

/* Thread-local string with reason for last prime_engine_new failure. */
const char* prime_last_error_message(void);

#ifdef __cplusplus
}
#endif

#endif /* PRIME_NET_H */
