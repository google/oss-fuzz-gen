#include <stdint.h>
#include <stddef.h>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_58(const uint8_t *data, size_t size) {
    CURL *easy_handle = curl_easy_init();
    if (easy_handle == NULL) {
        return 0; // Handle initialization failure
    }

    // Call the function-under-test
    curl_mime *mime = curl_mime_init(easy_handle);

    // Clean up
    if (mime != NULL) {
        curl_mime_free(mime);
    }
    curl_easy_cleanup(easy_handle);

    return 0;
}