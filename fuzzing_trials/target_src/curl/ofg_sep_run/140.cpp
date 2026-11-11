#include <curl/curl.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

extern "C" int LLVMFuzzerTestOneInput_140(const uint8_t *data, size_t size) {
    CURLM *multi_handle;
    struct curl_waitfd waitfd;
    unsigned int numfds = 0;
    CURLMcode result;

    // Initialize a multi handle
    multi_handle = curl_multi_init();
    if (multi_handle == NULL) {
        return 0;
    }

    // Initialize the waitfd structure
    waitfd.fd = 0; // Dummy file descriptor
    waitfd.events = CURL_WAIT_POLLIN; // Dummy event
    waitfd.revents = 0;

    // Call the function-under-test
    result = curl_multi_waitfds(multi_handle, &waitfd, 1, &numfds);

    // Clean up
    curl_multi_cleanup(multi_handle);

    return 0;
}