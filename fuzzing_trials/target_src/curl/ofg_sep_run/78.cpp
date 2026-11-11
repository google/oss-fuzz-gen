#include <stdint.h>
#include <stdlib.h>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_78(const uint8_t *data, size_t size) {
    // Initialize a CURL mime handle
    CURL *easy_handle = curl_easy_init();
    if (!easy_handle) {
        return 0; // If initialization fails, exit early
    }

    curl_mime *mime = curl_mime_init(easy_handle);
    if (!mime) {
        curl_easy_cleanup(easy_handle);
        return 0; // If mime initialization fails, exit early
    }

    // Call the function-under-test
    curl_mimepart *part = curl_mime_addpart(mime);

    // Clean up resources
    curl_mime_free(mime);
    curl_easy_cleanup(easy_handle);

    return 0;
}