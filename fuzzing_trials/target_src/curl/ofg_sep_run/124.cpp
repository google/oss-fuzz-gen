#include <curl/curl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput_124(const uint8_t *data, size_t size) {
    CURLM *multi_handle;
    struct curl_waitfd waitfd;
    int numfds;
    CURLMcode result;

    // Initialize CURL multi handle
    multi_handle = curl_multi_init();
    if (!multi_handle) {
        return 0;
    }

    // Initialize curl_waitfd structure
    waitfd.fd = 0; // File descriptor, 0 for standard input
    waitfd.events = CURL_WAIT_POLLIN; // Wait for read events
    waitfd.revents = 0; // Resulting events

    // Use the data to influence the timeout value
    int timeout_ms = 1000; // Default timeout
    if (size >= sizeof(int)) {
        memcpy(&timeout_ms, data, sizeof(int));
    }

    // Ensure timeout_ms is non-negative
    if (timeout_ms < 0) {
        timeout_ms = 1000;
    }

    // Call the function-under-test
    result = curl_multi_wait(multi_handle, &waitfd, 1, timeout_ms, &numfds);

    // Cleanup
    curl_multi_cleanup(multi_handle);

    return 0;
}