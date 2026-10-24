#include <curl/curl.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>  // Include for malloc and free

extern "C" int LLVMFuzzerTestOneInput_51(const uint8_t *data, size_t size) {
    // Initialize CURL
    CURL *curl = curl_easy_init();
    if (!curl) {
        return 0;
    }

    // Create a mime structure
    curl_mime *mime = curl_mime_init(curl);
    if (!mime) {
        curl_easy_cleanup(curl);
        return 0;
    }

    // Add a part to the mime structure
    curl_mimepart *part = curl_mime_addpart(mime);
    if (!part) {
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Ensure the data is null-terminated for string operations
    char *mime_type = (char *)malloc(size + 1);
    if (!mime_type) {
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        return 0;
    }
    memcpy(mime_type, data, size);
    mime_type[size] = '\0';

    // Call the function-under-test
    curl_mime_type(part, mime_type);

    // Clean up
    free(mime_type);
    curl_mime_free(mime);
    curl_easy_cleanup(curl);

    return 0;
}