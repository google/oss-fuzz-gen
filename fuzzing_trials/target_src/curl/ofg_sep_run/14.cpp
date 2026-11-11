#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_14(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

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

    // Ensure the name is null-terminated
    char *name = (char *)malloc(size + 1);
    if (!name) {
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        return 0;
    }
    memcpy(name, data, size);
    name[size] = '\0';

    // Call the function-under-test
    CURLcode result = curl_mime_name(part, name);

    // Clean up
    free(name);
    curl_mime_free(mime);
    curl_easy_cleanup(curl);

    return 0;
}