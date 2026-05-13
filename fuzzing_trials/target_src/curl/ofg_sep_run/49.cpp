#include <curl/curl.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput_49(const uint8_t *data, size_t size) {
    CURLM *multi_handle;
    CURL *easy_handle;
    int running_handles;
    CURLMcode result;

    // Initialize CURL globally
    curl_global_init(CURL_GLOBAL_DEFAULT);

    // Initialize a multi stack
    multi_handle = curl_multi_init();
    if (!multi_handle) {
        curl_global_cleanup();
        return 0;
    }

    // Initialize an easy handle
    easy_handle = curl_easy_init();
    if (!easy_handle) {
        curl_multi_cleanup(multi_handle);
        curl_global_cleanup();
        return 0;
    }

    // Set the URL option for the easy handle
    char *url = (char *)malloc(size + 1);
    if (url) {
        memcpy(url, data, size);
        url[size] = '\0'; // Null-terminate the URL
        curl_easy_setopt(easy_handle, CURLOPT_URL, url);

        // Add the easy handle to the multi handle
        curl_multi_add_handle(multi_handle, easy_handle);

        // Call the function-under-test
        result = curl_multi_socket_all(multi_handle, &running_handles);

        // Cleanup
        curl_multi_remove_handle(multi_handle, easy_handle);
        free(url);
    }

    curl_easy_cleanup(easy_handle);
    curl_multi_cleanup(multi_handle);
    curl_global_cleanup();

    return 0;
}