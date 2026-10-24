#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_132(const uint8_t *data, size_t size) {
    CURL *curl;
    CURLcode res;
    size_t sent = 0;
    curl_off_t offset = 0;
    unsigned int flags = 0;

    // Initialize a CURL session
    curl = curl_easy_init();
    if (curl) {
        // Set a dummy URL for the CURL session
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com");

        // Call the function-under-test
        res = curl_ws_send(curl, data, size, &sent, offset, flags);

        // Cleanup the CURL session
        curl_easy_cleanup(curl);
    }

    return 0;
}