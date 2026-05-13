#include <curl/curl.h>
#include <stdint.h>
#include <stdlib.h>

extern "C" int LLVMFuzzerTestOneInput_64(const uint8_t *data, size_t size) {
    CURLM *multi_handle;
    long timeout = 0;
    CURLMcode result;

    // Initialize CURL multi handle
    multi_handle = curl_multi_init();
    if (!multi_handle) {
        return 0;
    }

    // Call the function-under-test
    result = curl_multi_timeout(multi_handle, &timeout);

    // Cleanup CURL multi handle
    curl_multi_cleanup(multi_handle);

    return 0;
}