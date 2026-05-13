#include <stdint.h>
#include <stddef.h>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_3(const uint8_t *data, size_t size) {
    // Initialize CURLM handle
    CURLM *multi_handle = curl_multi_init();
    if (!multi_handle) {
        return 0;
    }

    // Ensure there's enough data to use for socket and other operations
    if (size < 2) {
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Initialize a curl_socket_t
    curl_socket_t sockfd = (curl_socket_t)(data[0] % 256); // Using first byte of data for socket

    // Initialize an integer for the third parameter
    int running_handles = 1; // Set to a non-NULL value

    // Create a CURL easy handle and add it to the multi handle
    CURL *easy_handle = curl_easy_init();
    if (!easy_handle) {
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Set a URL for the easy handle to use the second byte of data
    char url[256];
    snprintf(url, sizeof(url), "http://example.com/%d", data[1]);
    curl_easy_setopt(easy_handle, CURLOPT_URL, url);

    // Add the easy handle to the multi handle
    curl_multi_add_handle(multi_handle, easy_handle);

    // Call the function-under-test
    CURLMcode result = curl_multi_socket(multi_handle, sockfd, &running_handles);

    // Perform the multi handle
    int still_running;
    curl_multi_perform(multi_handle, &still_running);

    // Cleanup
    curl_multi_remove_handle(multi_handle, easy_handle);
    curl_easy_cleanup(easy_handle);
    curl_multi_cleanup(multi_handle);

    return 0;
}