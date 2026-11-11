#include <stdint.h>
#include <stdlib.h>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_25(const uint8_t *data, size_t size) {
    // Initialize a CURL handle
    CURL *curl = curl_easy_init();
    if(curl == NULL) {
        return 0; // Exit if initialization fails
    }

    // Set some basic options for the CURL handle
    // Here we use a fixed URL as the data is not used for URL setting
    curl_easy_setopt(curl, CURLOPT_URL, "http://example.com");

    // Call the function-under-test
    CURLcode result = curl_easy_upkeep(curl);

    // Cleanup the CURL handle
    curl_easy_cleanup(curl);

    return 0;
}