#include <curl/curl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput_138(const uint8_t *data, size_t size) {
    // Initialize CURLM and CURL handles
    CURLM *multi_handle = curl_multi_init();
    CURL *easy_handle = curl_easy_init();

    // Check if initialization was successful
    if (!multi_handle || !easy_handle) {
        if (multi_handle) curl_multi_cleanup(multi_handle);
        if (easy_handle) curl_easy_cleanup(easy_handle);
        return 0;
    }

    // Convert fuzz input data to a string and set it as the URL
    char *url = (char *)malloc(size + 1);
    if (url == NULL) {
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }
    memcpy(url, data, size);
    url[size] = '\0';

    // Set some options for the easy handle
    curl_easy_setopt(easy_handle, CURLOPT_URL, url);
    curl_easy_setopt(easy_handle, CURLOPT_WRITEFUNCTION, NULL);

    // Add the easy handle to the multi handle
    CURLMcode result = curl_multi_add_handle(multi_handle, easy_handle);

    if (result == CURLM_OK) {
        int still_running;
        // Perform the request
        curl_multi_perform(multi_handle, &still_running);

        // Wait for the transfers to complete
        while (still_running) {
            curl_multi_perform(multi_handle, &still_running);
        }
    }

    // Clean up
    curl_multi_remove_handle(multi_handle, easy_handle);
    curl_easy_cleanup(easy_handle);
    curl_multi_cleanup(multi_handle);
    free(url);

    return 0;
}