#include <curl/curl.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_90(const uint8_t *data, size_t size) {
    CURL *curl;
    CURLcode res;
    size_t sent_bytes = 0;

    if (size == 0) {
        return 0;
    }

    // Initialize a CURL session
    curl = curl_easy_init();
    if (!curl) {
        return 0;
    }

    // Set URL to connect to (using a dummy URL for fuzzing purposes)
    curl_easy_setopt(curl, CURLOPT_URL, "http://example.com");

    // Set the connection to be non-blocking
    curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1L);

    // Perform the connection
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        return 0;
    }

    // Attempt to send data
    res = curl_easy_send(curl, data, size, &sent_bytes);

    // Clean up the CURL session
    curl_easy_cleanup(curl);

    return 0;
}