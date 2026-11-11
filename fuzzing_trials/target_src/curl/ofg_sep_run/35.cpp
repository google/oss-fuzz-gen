#include <curl/curl.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>  // For malloc and free
#include <string.h>  // For memcpy

extern "C" int LLVMFuzzerTestOneInput_35(const uint8_t *data, size_t size) {
    CURL *curl;
    curl_mime *mime;
    curl_mimepart *part;
    struct curl_slist *headers = NULL;
    int take_ownership = 1; // Non-zero value to take ownership of the headers

    // Initialize CURL
    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if (!curl) {
        curl_global_cleanup();
        return 0;
    }

    // Initialize MIME
    mime = curl_mime_init(curl);
    if (!mime) {
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        return 0;
    }

    // Add a part to the MIME
    part = curl_mime_addpart(mime);
    if (!part) {
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        return 0;
    }

    // Create headers from fuzz data
    if (size > 0) {
        // Create a single header from the data
        char *header = (char *)malloc(size + 1);
        if (header) {
            memcpy(header, data, size);
            header[size] = '\0'; // Null-terminate the string
            headers = curl_slist_append(headers, header);
            free(header);
        }
    }

    // Call the function-under-test
    curl_mime_headers(part, headers, take_ownership);

    // Cleanup
    curl_mime_free(mime);
    curl_easy_cleanup(curl);
    curl_global_cleanup();

    return 0;
}