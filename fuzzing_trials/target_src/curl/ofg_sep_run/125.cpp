#include <curl/curl.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

extern "C" int LLVMFuzzerTestOneInput_125(const uint8_t *data, size_t size) {
    CURLM *multi_handle = curl_multi_init();
    struct curl_waitfd waitfd;
    int numfds;
    CURLMcode result;

    if (multi_handle == NULL) {
        return 0;
    }

    // Initialize waitfd with non-NULL values
    waitfd.fd = 0; // Typically a file descriptor, using 0 for stdin as a placeholder
    waitfd.events = CURL_WAIT_POLLIN; // Wait for incoming data
    waitfd.revents = 0; // No events occurred yet

    // Use data from the fuzzer as input for the timeout
    unsigned int timeout_ms = size > 0 ? data[0] : 1; // Ensure non-zero timeout
    int timeout = (int)timeout_ms;

    // Call the function-under-test
    result = curl_multi_wait(multi_handle, &waitfd, 1, timeout, &numfds);

    // Cleanup
    curl_multi_cleanup(multi_handle);

    return 0;
}