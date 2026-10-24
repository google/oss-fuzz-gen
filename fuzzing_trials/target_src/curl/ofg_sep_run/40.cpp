#include <curl/curl.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput_40(const uint8_t *data, size_t size) {
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

    // Ensure that the filename is null-terminated
    char filename[256];
    size_t filename_len = size < 255 ? size : 255;
    memcpy(filename, data, filename_len);
    filename[filename_len] = '\0';

    // Call the function-under-test
    curl_mime_filename(part, filename);

    // Clean up
    curl_mime_free(mime);
    curl_easy_cleanup(curl);

    return 0;
}