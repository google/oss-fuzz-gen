#include <cstdint>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_86(const uint8_t *data, size_t size) {
    // Initialize a CURLM handle
    CURLM *multi_handle = curl_multi_init();
    if (!multi_handle) {
        return 0;
    }

    // Call the function-under-test
    CURLMcode result = curl_multi_wakeup(multi_handle);

    // Clean up the CURLM handle
    curl_multi_cleanup(multi_handle);

    return 0;
}