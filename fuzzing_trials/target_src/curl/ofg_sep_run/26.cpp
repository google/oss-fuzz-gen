#include <stdint.h>
#include <stddef.h>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_26(const uint8_t *data, size_t size) {
    // Initialize a CURL handle
    CURL *curl = curl_easy_init();
    if (!curl) {
        return 0; // If initialization fails, exit the fuzzer
    }

    // Set some options to ensure the CURL handle is in a valid state
    curl_easy_setopt(curl, CURLOPT_URL, "http://example.com");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    // Call the function-under-test
    CURLcode result = curl_easy_upkeep(curl);

    // Cleanup the CURL handle
    curl_easy_cleanup(curl);

    return 0;
}