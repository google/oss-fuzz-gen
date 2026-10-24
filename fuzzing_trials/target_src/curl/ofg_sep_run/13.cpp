#include <curl/curl.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h> // Include for malloc and free

// Ensure C linkage for the function-under-test
extern "C" {
    CURLcode curl_mime_name(curl_mimepart *, const char *);
}

extern "C" int LLVMFuzzerTestOneInput_13(const uint8_t *data, size_t size) {
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

    // Ensure the data is null-terminated for use as a string
    char *name = (char *)malloc(size + 1);
    if (!name) {
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        return 0;
    }
    memcpy(name, data, size);
    name[size] = '\0';

    // Call the function-under-test
    curl_mime_name(part, name);

    // Clean up
    free(name);
    curl_mime_free(mime);
    curl_easy_cleanup(curl);

    return 0;
}