#include <curl/curl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput_8(const uint8_t *data, size_t size) {
    CURL *curl;
    CURLcode res;
    size_t n = 0;

    // Initialize a CURL session
    curl = curl_easy_init();
    if (!curl) {
        return 0;
    }

    // Set a URL (required for initialization)
    curl_easy_setopt(curl, CURLOPT_URL, "http://example.com");

    // Perform the request to establish a connection
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        return 0;
    }

    // Initialize a buffer to receive data
    void *buffer = malloc(size);
    if (!buffer) {
        curl_easy_cleanup(curl);
        return 0;
    }

    // Copy data to the buffer
    memcpy(buffer, data, size);

    // Call the function-under-test
    // Note: curl_easy_recv requires a connection to be established first
    res = curl_easy_recv(curl, buffer, size, &n);

    // Clean up
    free(buffer);
    curl_easy_cleanup(curl);

    return 0;
}