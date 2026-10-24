#include <stdint.h>
#include <stddef.h>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_120(const uint8_t *data, size_t size) {
    CURL *easy = curl_easy_init();
    if (!easy) {
        return 0;
    }

    // Initialize curl_mime and curl_mimepart
    curl_mime *mime = curl_mime_init(easy);
    if (!mime) {
        curl_easy_cleanup(easy);
        return 0;
    }

    curl_mimepart *part = curl_mime_addpart(mime);
    if (!part) {
        curl_mime_free(mime);
        curl_easy_cleanup(easy);
        return 0;
    }

    // Call the function-under-test
    CURLcode result = curl_mime_subparts(part, mime);

    // Clean up
    curl_mime_free(mime);
    curl_easy_cleanup(easy);

    return 0;
}