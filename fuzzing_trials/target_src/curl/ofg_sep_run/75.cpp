#include <stdint.h>
#include <stddef.h>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_75(const uint8_t *data, size_t size) {
    // Initialize a CURLM handle
    CURLM *multi_handle = curl_multi_init();
    if (multi_handle == NULL) {
        return 0; // If initialization fails, exit early
    }

    // Initialize a CURL easy handle
    CURL *easy_handle = curl_easy_init();
    if (easy_handle == NULL) {
        curl_multi_cleanup(multi_handle);
        return 0; // If initialization fails, exit early
    }

    // Set the easy handle with some options
    curl_easy_setopt(easy_handle, CURLOPT_URL, "http://example.com");
    curl_easy_setopt(easy_handle, CURLOPT_POSTFIELDS, data);
    curl_easy_setopt(easy_handle, CURLOPT_POSTFIELDSIZE, size);

    // Add the easy handle to the multi handle
    curl_multi_add_handle(multi_handle, easy_handle);

    // Perform the multi handle operations
    int still_running;
    curl_multi_perform(multi_handle, &still_running);

    // Clean up the handles
    curl_multi_remove_handle(multi_handle, easy_handle);
    curl_easy_cleanup(easy_handle);
    curl_multi_cleanup(multi_handle);

    return 0;
}