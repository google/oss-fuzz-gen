#include <curl/curl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput_55(const uint8_t *data, size_t size) {
    CURL *curl;
    CURLcode res;
    int pause_bitmask;

    // Initialize CURL
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if(curl) {
        // Ensure size is large enough to use more data
        if (size > 1) {
            // Use the first byte of data to determine the pause bitmask
            pause_bitmask = data[0] % (CURLPAUSE_RECV | CURLPAUSE_SEND | CURLPAUSE_ALL);

            // Set some options to make the call more meaningful
            curl_easy_setopt(curl, CURLOPT_URL, "http://example.com");

            // If size is large enough, use additional bytes for other options
            if (size > 2) {
                // Use the second byte to set a timeout
                long timeout = data[1] % 100; // Timeout in seconds
                curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
            }

            // Call the function-under-test
            res = curl_easy_pause(curl, pause_bitmask);

            // Check the result if needed (for debugging purposes)
            // printf("curl_easy_pause result: %d\n", res);
        }

        // Cleanup
        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();
    return 0;
}