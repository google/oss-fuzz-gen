#include <curl/curl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput_135(const uint8_t *data, size_t size) {
    CURL *curl;
    CURLcode res;
    void *recv_buffer;
    size_t recv_size;
    const struct curl_ws_frame *frame;

    // Initialize CURL
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if(curl) {
        // Allocate a buffer for receiving data
        recv_buffer = malloc(size);
        if (recv_buffer == NULL) {
            curl_easy_cleanup(curl);
            curl_global_cleanup();
            return 0;
        }

        // Copy the input data to the receive buffer
        memcpy(recv_buffer, data, size);

        // Initialize the recv_size
        recv_size = size;

        // Call the function-under-test
        res = curl_ws_recv(curl, recv_buffer, size, &recv_size, &frame);

        // Clean up
        free(recv_buffer);
        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();
    return 0;
}