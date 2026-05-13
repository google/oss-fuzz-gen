#include <curl/curl.h>
#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput_2(const uint8_t *data, size_t size) {
    CURLM *multi_handle = curl_multi_init();
    CURL **handles = nullptr;

    if (multi_handle == nullptr) {
        return 0;
    }

    // Call the function-under-test
    handles = curl_multi_get_handles(multi_handle);

    // Clean up
    curl_multi_cleanup(multi_handle);

    return 0;
}