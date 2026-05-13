#include <curl/curl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput_129(const uint8_t *data, size_t size) {
    // Initialize a CURLM handle
    CURLM *multi_handle = curl_multi_init();
    
    if (multi_handle == NULL) {
        // If initialization fails, return immediately
        return 0;
    }

    // Initialize a CURL easy handle
    CURL *easy_handle = curl_easy_init();
    if (easy_handle == NULL) {
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Create a null-terminated string from the input data
    char *url = (char *)malloc(size + 1);
    if (url == NULL) {
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }
    memcpy(url, data, size);
    url[size] = '\0';  // Null-terminate the string

    // Set the URL for the CURL easy handle
    curl_easy_setopt(easy_handle, CURLOPT_URL, url);

    // Add the easy handle to the multi handle
    curl_multi_add_handle(multi_handle, easy_handle);

    // Perform the request
    int still_running;
    curl_multi_perform(multi_handle, &still_running);

    // Cleanup
    free(url);
    curl_multi_remove_handle(multi_handle, easy_handle);
    curl_easy_cleanup(easy_handle);
    curl_multi_cleanup(multi_handle);

    return 0;
}