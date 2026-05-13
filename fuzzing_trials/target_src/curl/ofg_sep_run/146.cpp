#include <stdint.h>
#include <stddef.h>
#include <curl/curl.h>
#include <string.h>
#include <stdlib.h>  // Include for malloc and free

extern "C" int LLVMFuzzerTestOneInput_146(const uint8_t *data, size_t size) {
    CURLM *multi_handle;
    CURL *easy_handle;
    CURLMcode result;

    // Initialize CURL globally
    curl_global_init(CURL_GLOBAL_DEFAULT);

    // Create a multi handle
    multi_handle = curl_multi_init();
    if (!multi_handle) {
        curl_global_cleanup();
        return 0;
    }

    // Create an easy handle
    easy_handle = curl_easy_init();
    if (!easy_handle) {
        curl_multi_cleanup(multi_handle);
        curl_global_cleanup();
        return 0;
    }

    // Convert input data to a string and use it as a URL if possible
    if (size > 0) {
        char *url = (char *)malloc(size + 1);
        if (url) {
            memcpy(url, data, size);
            url[size] = '\0'; // Null-terminate the string

            // Set the URL from the fuzzing input
            curl_easy_setopt(easy_handle, CURLOPT_URL, url);

            // Add the easy handle to the multi handle
            curl_multi_add_handle(multi_handle, easy_handle);

            // Perform the request
            int still_running;
            curl_multi_perform(multi_handle, &still_running);

            // Remove the easy handle from the multi handle
            result = curl_multi_remove_handle(multi_handle, easy_handle);

            free(url);
        }
    }

    // Cleanup
    curl_easy_cleanup(easy_handle);
    curl_multi_cleanup(multi_handle);
    curl_global_cleanup();

    return 0;
}