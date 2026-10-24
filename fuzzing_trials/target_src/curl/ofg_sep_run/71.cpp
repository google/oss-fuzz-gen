#include <curl/curl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

extern "C" int LLVMFuzzerTestOneInput_71(const uint8_t *data, size_t size) {
    CURLM *multi_handle;
    struct curl_waitfd waitfd;
    int numfds;
    CURLMcode result;

    // Initialize libcurl
    curl_global_init(CURL_GLOBAL_DEFAULT);

    // Initialize a multi stack
    multi_handle = curl_multi_init();
    if (!multi_handle) {
        curl_global_cleanup();
        return 0;
    }

    // Initialize waitfd structure
    memset(&waitfd, 0, sizeof(waitfd));
    waitfd.fd = 0; // File descriptor, set to 0 for testing
    waitfd.events = CURL_WAIT_POLLIN; // Set to poll for input

    // Use the first byte of data to determine the timeout value
    int timeout = (size > 0) ? data[0] : 1000; // Default timeout 1000ms

    // Call the function-under-test
    result = curl_multi_poll(multi_handle, &waitfd, 1, timeout, &numfds);

    // Cleanup
    curl_multi_cleanup(multi_handle);
    curl_global_cleanup();

    return 0;
}