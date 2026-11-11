#include <curl/curl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput_19(const uint8_t *data, size_t size) {
    // Initialize CURL
    CURL *curl = curl_easy_init();
    if (!curl) {
        return 0;
    }

    // Set default URL to avoid NULL URL issues
    curl_easy_setopt(curl, CURLOPT_URL, "http://example.com");

    char *postData = nullptr;
    // If data is available, use it to set some options
    if (size > 0) {
        // Convert data to a string for CURLOPT_POSTFIELDS
        postData = (char *)malloc(size + 1);
        if (postData) {
            memcpy(postData, data, size);
            postData[size] = '\0';  // Null-terminate the string

            // Set POST data
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData);
        }
    }

    // Perform the CURL operation
    CURLcode res = curl_easy_perform(curl);

    // Clean up
    curl_easy_cleanup(curl);
    free(postData);

    return 0;
}