#include <stdint.h>
#include <stdlib.h>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_114(const uint8_t *data, size_t size) {
    // Initialize the CURLM handle
    CURLM *multi_handle = curl_multi_init();
    if (!multi_handle) {
        return 0; // Exit if initialization fails
    }

    // Initialize a CURL handle
    CURL *easy_handle = curl_easy_init();
    if (!easy_handle) {
        curl_multi_cleanup(multi_handle);
        return 0; // Exit if initialization fails
    }

    // Set the URL option for the CURL handle
    curl_easy_setopt(easy_handle, CURLOPT_URL, "http://example.com");

    // Add the easy handle to the multi handle
    curl_multi_add_handle(multi_handle, easy_handle);

    // Perform the multi handle operation
    int still_running = 0;
    curl_multi_perform(multi_handle, &still_running);

    // Initialize an integer to store the number of remaining messages
    int msgs_in_queue = 0;

    // Call the function-under-test
    CURLMsg *msg = curl_multi_info_read(multi_handle, &msgs_in_queue);

    // Clean up the CURL handles
    curl_multi_remove_handle(multi_handle, easy_handle);
    curl_easy_cleanup(easy_handle);
    curl_multi_cleanup(multi_handle);

    return 0;
}