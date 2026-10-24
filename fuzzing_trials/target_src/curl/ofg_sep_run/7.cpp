#include <curl/curl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput_7(const uint8_t *data, size_t size) {
    CURL *curl;
    CURLcode res;

    // Initialize CURL
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (!curl) {
        curl_global_cleanup();
        return 0;
    }

    // Convert fuzz input into a null-terminated string
    char *url = (char *)malloc(size + 1);
    if (url == NULL) {
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        return 0;
    }
    memcpy(url, data, size);
    url[size] = '\0'; // Ensure null-termination

    // Setup the URL for CURL
    curl_easy_setopt(curl, CURLOPT_URL, url);

    // Perform the CURL operation
    res = curl_easy_perform(curl);

    // Cleanup
    free(url);
    curl_easy_cleanup(curl);
    curl_global_cleanup();

    return 0;
}