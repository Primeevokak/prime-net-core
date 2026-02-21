#include <stdio.h>
#include <string.h>

#include "../../include/prime_net.h"

static void on_progress(uint64_t downloaded, uint64_t total, double speed_mbps, void* user_data) {
    (void)user_data;
    fprintf(stderr, "progress: %llu/%llu bytes (%.2f Mbps)\n",
            (unsigned long long)downloaded,
            (unsigned long long)total,
            speed_mbps);
}

int main(void) {
    PrimeEngine* engine = prime_engine_new(NULL);
    if (!engine) {
        const char* err = prime_last_error_message();
        fprintf(stderr, "engine init failed: %s\n", err ? err : "unknown error");
        return 1;
    }

    const char* headers[] = {"Accept: */*"};
    PrimeRequest request;
    memset(&request, 0, sizeof(request));
    request.url = "https://example.com";
    request.method = "GET";
    request.headers = headers;
    request.headers_count = 1;

    PrimeResponse* response = prime_engine_fetch(engine, &request, on_progress, NULL);
    if (!response) {
        fprintf(stderr, "fetch failed: null response\n");
        prime_engine_free(engine);
        return 2;
    }

    if (response->error_code != 0) {
        fprintf(stderr, "fetch error: (%d) %s\n",
                response->error_code,
                response->error_message ? response->error_message : "unknown");
    } else {
        printf("status=%u, body_len=%zu\n", response->status_code, response->body_len);
    }

    prime_response_free(response);

    /* Async + cancellation example (best-effort). */
    PrimeRequestHandle* h = prime_engine_fetch_async(engine, &request, on_progress, NULL);
    if (!h) {
        fprintf(stderr, "fetch_async failed\n");
        prime_engine_free(engine);
        return 3;
    }

    PrimeRequestStatus st = prime_request_status(h);
    fprintf(stderr, "async status=%d\n", (int)st);

    /* In a UI, you'd call this from another thread when the user cancels. */
    (void)prime_request_cancel(h);

    PrimeResponse* r2 = prime_request_wait(h, 5000);
    if (r2 && r2->error_code != 0) {
        fprintf(stderr, "async cancelled: (%d) %s\n",
                r2->error_code,
                r2->error_message ? r2->error_message : "unknown");
    }
    prime_response_free(r2);

    prime_engine_free(engine);
    return 0;
}
