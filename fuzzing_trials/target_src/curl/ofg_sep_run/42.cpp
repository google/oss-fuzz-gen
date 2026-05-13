#include <curl/curl.h>
#include <stdint.h>
#include <stdlib.h>

extern "C" int LLVMFuzzerTestOneInput_42(const uint8_t *data, size_t size) {
    CURL *original_handle;
    CURL *duplicate_handle;

    // Initialize CURL library
    curl_global_init(CURL_GLOBAL_DEFAULT);

    // Create a CURL easy handle
    original_handle = curl_easy_init();
    if (!original_handle) {
        curl_global_cleanup();
        return 0;
    }

    // Set some options on the original handle to ensure it's not NULL
    curl_easy_setopt(original_handle, CURLOPT_URL, "http://example.com");
    curl_easy_setopt(original_handle, CURLOPT_VERBOSE, 1L);

    // Duplicate the CURL easy handle
    duplicate_handle = curl_easy_duphandle(original_handle);

    // Cleanup the handles
    if (duplicate_handle) {
        curl_easy_cleanup(duplicate_handle);
    }
    curl_easy_cleanup(original_handle);

    // Cleanup CURL library
    curl_global_cleanup();

    return 0;
}