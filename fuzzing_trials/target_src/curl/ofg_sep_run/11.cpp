#include <cstddef>
#include <cstdint>
#include <cstring> // Include for memcpy
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_11(const uint8_t *data, size_t size) {
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

    // Ensure the data is null-terminated by copying it to a new buffer
    char *data_copy = new char[size + 1];
    if (!data_copy) {
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        return 0;
    }
    memcpy(data_copy, data, size);
    data_copy[size] = '\0';

    // Call the function-under-test
    CURLcode result = curl_mime_data(part, data_copy, size);

    // Clean up
    delete[] data_copy;
    curl_mime_free(mime);
    curl_easy_cleanup(curl);

    return 0;
}