#include <curl/curl.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_91(const uint8_t *data, size_t size) {
    CURL *curl;
    CURLcode res;
    size_t sent_bytes = 0;

    // Initialize CURL
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if(curl) {
        // Set a dummy URL to ensure curl_easy_send can be called
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com");

        // Attempt to send the data
        res = curl_easy_send(curl, (const void *)data, size, &sent_bytes);

        // Cleanup
        curl_easy_cleanup(curl);
    }

    // Clean up CURL global environment
    curl_global_cleanup();

    return 0;
}