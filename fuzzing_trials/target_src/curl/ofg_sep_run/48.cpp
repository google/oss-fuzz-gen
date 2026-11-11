#include <curl/curl.h>
#include <stdint.h>
#include <stddef.h>

extern "C" int LLVMFuzzerTestOneInput_48(const uint8_t *data, size_t size) {
    CURLM *multi_handle;
    int running_handles;

    // Initialize a CURLM handle
    multi_handle = curl_multi_init();
    if (!multi_handle) {
        return 0; // If initialization fails, exit early
    }

    // Call the function-under-test
    CURLMcode result = curl_multi_socket_all(multi_handle, &running_handles);

    // Clean up
    curl_multi_cleanup(multi_handle);

    return 0;
}