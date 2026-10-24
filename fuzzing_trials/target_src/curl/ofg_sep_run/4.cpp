#include <curl/curl.h>
#include <stdint.h>
#include <stdlib.h>

extern "C" int LLVMFuzzerTestOneInput_4(const uint8_t *data, size_t size) {
    CURLM *multi_handle;
    curl_socket_t sockfd;
    int running_handles;

    // Initialize libcurl
    curl_global_init(CURL_GLOBAL_DEFAULT);

    // Create a multi handle
    multi_handle = curl_multi_init();
    if (!multi_handle) {
        curl_global_cleanup();
        return 0;
    }

    // Assign a socket file descriptor from the fuzzing data
    // Ensure the size is large enough to extract a valid socket descriptor
    if (size < sizeof(curl_socket_t)) {
        curl_multi_cleanup(multi_handle);
        curl_global_cleanup();
        return 0;
    }
    sockfd = *(const curl_socket_t *)data;

    // Call the function-under-test
    CURLMcode result = curl_multi_socket(multi_handle, sockfd, &running_handles);

    // Cleanup
    curl_multi_cleanup(multi_handle);
    curl_global_cleanup();

    return 0;
}