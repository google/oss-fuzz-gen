#include <stdint.h>
#include <stddef.h>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_39(const uint8_t *data, size_t size) {
    // Initialize the library
    curl_global_init(CURL_GLOBAL_DEFAULT);

    // Call the function-under-test
    curl_global_cleanup();

    return 0;
}