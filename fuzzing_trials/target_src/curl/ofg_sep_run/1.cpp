#include <stdint.h>
#include <stddef.h>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_1(const uint8_t *data, size_t size) {
    CURLM *multi_handle = curl_multi_init();
    CURL **handles = NULL;

    if (multi_handle == NULL) {
        return 0;
    }

    // Call the function-under-test
    handles = curl_multi_get_handles(multi_handle);

    // Clean up
    curl_multi_cleanup(multi_handle);

    return 0;
}