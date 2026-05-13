#include <curl/curl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput_65(const uint8_t *data, size_t size) {
    // Initialize CURLM handle
    CURLM *multi_handle = curl_multi_init();
    if (!multi_handle) {
        return 0; // If initialization fails, exit early
    }

    // Create a new easy handle
    CURL *easy_handle = curl_easy_init();
    if (!easy_handle) {
        curl_multi_cleanup(multi_handle);
        return 0; // Exit if easy handle initialization fails
    }

    // Convert the input data to a null-terminated string
    char *url = (char *)malloc(size + 1);
    if (!url) {
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0; // Exit if memory allocation fails
    }
    memcpy(url, data, size);
    url[size] = '\0'; // Null-terminate the string

    // Set the URL for the easy handle
    curl_easy_setopt(easy_handle, CURLOPT_URL, url);

    // Add the easy handle to the multi handle
    curl_multi_add_handle(multi_handle, easy_handle);

    // Initialize a long variable for the timeout
    long timeout = 0;

    // Call the function-under-test
    CURLMcode result = curl_multi_timeout(multi_handle, &timeout);

    // Perform the multi handle actions
    int still_running = 0;
    curl_multi_perform(multi_handle, &still_running);

    // Clean up the easy handle
    curl_easy_cleanup(easy_handle);

    // Clean up the CURLM handle
    curl_multi_cleanup(multi_handle);

    // Free the allocated URL
    free(url);

    return 0;
}