#include <curl/curl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput_134(const uint8_t *data, size_t size) {
    CURL *curl;
    CURLcode res;
    void *buffer;
    size_t buffer_size = size;
    size_t received_size = 0;
    const struct curl_ws_frame *frame = NULL;

    // Initialize CURL
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (!curl) {
        curl_global_cleanup();
        return 0;
    }

    // Allocate a buffer and copy the input data into it
    buffer = malloc(buffer_size);
    if (buffer == NULL) {
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        return 0;
    }
    memcpy(buffer, data, size);

    // Set CURL options for WebSocket (assuming a valid WebSocket URL is set)
    curl_easy_setopt(curl, CURLOPT_URL, "ws://example.com"); // Example URL
    curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1L);

    // Perform the connection
    res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        // Call the function under test
        res = curl_ws_recv(curl, buffer, buffer_size, &received_size, &frame);
    }

    // Clean up
    free(buffer);
    curl_easy_cleanup(curl);
    curl_global_cleanup();

    return 0;
}