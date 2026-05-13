#include <stdint.h>
#include <stddef.h>
#include <curl/curl.h>
#include <string.h>
#include <stdlib.h>

extern "C" int LLVMFuzzerTestOneInput_130(const uint8_t *data, size_t size) {
    // Initialize the CURL library
    if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
        return 0; // If initialization failed, return early
    }

    // Initialize the CURL multi handle
    CURLM *multi_handle = curl_multi_init();
    
    // Check if the multi handle was initialized successfully
    if (multi_handle == NULL) {
        curl_global_cleanup();
        return 0; // If initialization failed, return early
    }

    // Initialize the CURL easy handle
    CURL *easy_handle = curl_easy_init();
    
    if (easy_handle == NULL) {
        curl_multi_cleanup(multi_handle);
        curl_global_cleanup();
        return 0; // If initialization failed, return early
    }

    // Create a null-terminated string from the input data
    char *url = (char *)malloc(size + 1);
    if (url == NULL) {
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        curl_global_cleanup();
        return 0;
    }
    memcpy(url, data, size);
    url[size] = '\0'; // Ensure null-termination

    // Set the URL for the easy handle
    curl_easy_setopt(easy_handle, CURLOPT_URL, url);

    // Add the easy handle to the multi handle
    curl_multi_add_handle(multi_handle, easy_handle);

    // Perform the request
    int still_running;
    do {
        curl_multi_perform(multi_handle, &still_running);
    } while (still_running);

    // Cleanup
    curl_multi_remove_handle(multi_handle, easy_handle);
    curl_easy_cleanup(easy_handle);
    curl_multi_cleanup(multi_handle);
    curl_global_cleanup();
    free(url);

    return 0;
}