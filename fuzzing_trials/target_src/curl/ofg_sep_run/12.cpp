#include <curl/curl.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput_12(const uint8_t *data, size_t size) {
    CURL *curl;
    curl_mime *mime;
    curl_mimepart *part;
    CURLcode res;

    // Initialize CURL
    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if (!curl) {
        curl_global_cleanup();
        return 0;
    }

    // Create a mime handle
    mime = curl_mime_init(curl);
    if (!mime) {
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        return 0;
    }

    // Add a part to the mime
    part = curl_mime_addpart(mime);
    if (!part) {
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        return 0;
    }

    // Ensure the data is null-terminated for safety
    char *data_copy = new char[size + 1];
    memcpy(data_copy, data, size);
    data_copy[size] = '\0';

    // Call the function-under-test
    res = curl_mime_data(part, data_copy, size);

    // Clean up
    delete[] data_copy;
    curl_mime_free(mime);
    curl_easy_cleanup(curl);
    curl_global_cleanup();

    return 0;
}