#include <curl/curl.h>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdlib>  // For malloc and free

extern "C" int LLVMFuzzerTestOneInput_50(const uint8_t *data, size_t size) {
    // Initialize a CURL mime part
    CURL *curl = curl_easy_init();
    if (!curl) {
        return 0;
    }

    curl_mime *mime = curl_mime_init(curl);
    if (!mime) {
        curl_easy_cleanup(curl);
        return 0;
    }

    curl_mimepart *part = curl_mime_addpart(mime);
    if (!part) {
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Ensure the data is null-terminated for use as a string
    char *mime_type = (char *)malloc(size + 1);
    if (!mime_type) {
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        return 0;
    }
    memcpy(mime_type, data, size);
    mime_type[size] = '\0';

    // Call the function-under-test
    CURLcode result = curl_mime_type(part, mime_type);

    // Clean up
    free(mime_type);
    curl_mime_free(mime);
    curl_easy_cleanup(curl);

    return 0;
}