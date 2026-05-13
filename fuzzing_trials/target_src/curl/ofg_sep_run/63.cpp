#include <curl/curl.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput_63(const uint8_t *data, size_t size) {
    CURL *curl;
    CURLcode res;
    CURLINFO info;
    long response_code;

    // Initialize CURL
    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if (curl == NULL) {
        curl_global_cleanup();
        return 0;
    }

    // Set URL to a non-NULL value
    char url[] = "http://example.com";
    curl_easy_setopt(curl, CURLOPT_URL, url);

    // Ensure data size is sufficient for CURLINFO
    if (size < sizeof(CURLINFO)) {
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        return 0;
    }

    // Copy data to CURLINFO type
    memcpy(&info, data, sizeof(CURLINFO));

    // Perform the request
    res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        // Call the function-under-test
        curl_easy_getinfo(curl, info, &response_code);
    }

    // Cleanup
    curl_easy_cleanup(curl);
    curl_global_cleanup();

    return 0;
}