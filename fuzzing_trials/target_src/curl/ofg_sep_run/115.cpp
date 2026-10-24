#include <curl/curl.h>
#include <cstdint>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput_115(const uint8_t *data, size_t size) {
    // Initialize CURLM pointer
    CURLM *multi_handle = curl_multi_init();
    if (!multi_handle) {
        return 0; // Return if initialization fails
    }

    // Create an easy handle
    CURL *easy_handle = curl_easy_init();
    if (!easy_handle) {
        curl_multi_cleanup(multi_handle);
        return 0; // Return if initialization fails
    }

    // Set the URL for the easy handle
    curl_easy_setopt(easy_handle, CURLOPT_URL, "http://example.com");

    // Add the easy handle to the multi handle
    curl_multi_add_handle(multi_handle, easy_handle);

    // Perform the multi handle operation
    int still_running = 0;
    curl_multi_perform(multi_handle, &still_running);

    // Initialize an integer for the number of messages left
    int msgs_left = 0;

    // Call the function-under-test
    CURLMsg *msg = nullptr;
    do {
        msg = curl_multi_info_read(multi_handle, &msgs_left);
    } while (msg);

    // Clean up the easy handle
    curl_multi_remove_handle(multi_handle, easy_handle);
    curl_easy_cleanup(easy_handle);

    // Clean up the CURLM handle
    curl_multi_cleanup(multi_handle);

    return 0;
}