#include <curl/curl.h>
#include <stdint.h>
#include <stdlib.h>

extern "C" int LLVMFuzzerTestOneInput_70(const uint8_t *data, size_t size) {
    CURLM *multi_handle;
    CURLMcode res;
    struct curl_waitfd waitfd;
    int numfds;

    // Initialize libcurl
    curl_global_init(CURL_GLOBAL_DEFAULT);

    // Initialize a multi stack
    multi_handle = curl_multi_init();
    if (!multi_handle) {
        curl_global_cleanup();
        return 0;
    }

    // Initialize the curl_waitfd structure
    waitfd.fd = 0; // File descriptor, 0 is typically stdin, using it as a placeholder
    waitfd.events = CURL_WAIT_POLLIN; // Ready to read
    waitfd.revents = 0; // Resulting events, initially set to 0

    // Use a non-zero timeout value
    int timeout_ms = 1000; // 1 second timeout

    // Call the function-under-test
    res = curl_multi_poll(multi_handle, &waitfd, 1, timeout_ms, &numfds);

    // Clean up
    curl_multi_cleanup(multi_handle);
    curl_global_cleanup();

    return 0;
}