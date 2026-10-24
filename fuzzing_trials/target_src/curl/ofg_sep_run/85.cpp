#include <stdint.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput_85(const uint8_t *data, size_t size) {
    CURLM *multi_handle = curl_multi_init();
    if (multi_handle == NULL) {
        return 0; // Exit if initialization fails
    }

    CURL *easy_handle = curl_easy_init();
    if (easy_handle == NULL) {
        curl_multi_cleanup(multi_handle);
        return 0; // Exit if initialization fails
    }

    // Use the input data as a URL if possible, or a portion of it
    char url[256];
    snprintf(url, sizeof(url), "http://example.com/%.*s", (int)size, data);

    // Set the URL for the easy handle
    curl_easy_setopt(easy_handle, CURLOPT_URL, url);

    // Add the easy handle to the multi handle
    curl_multi_add_handle(multi_handle, easy_handle);

    // Call the function-under-test
    CURLMcode result = curl_multi_wakeup(multi_handle);

    // Perform the multi handle actions
    int still_running;
    curl_multi_perform(multi_handle, &still_running);

    // Clean up
    curl_multi_remove_handle(multi_handle, easy_handle);
    curl_easy_cleanup(easy_handle);
    curl_multi_cleanup(multi_handle);

    return 0;
}