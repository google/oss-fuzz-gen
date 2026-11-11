#include <curl/curl.h>
#include <cstdint>
#include <cstdlib>
#include <cstdio> // Include for fprintf and stderr

extern "C" int LLVMFuzzerTestOneInput_54(const uint8_t *data, size_t size) {
    CURL *curl;
    CURLcode res;
    int pause_option;

    // Initialize CURL
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if(curl) {
        // Ensure the size is large enough to extract an integer
        if (size >= sizeof(int)) {
            // Extract an int from the data for the pause option
            pause_option = *(reinterpret_cast<const int*>(data));

            // Call the function-under-test
            res = curl_easy_pause(curl, pause_option);

            // Check the result (optional, for debugging purposes)
            if(res != CURLE_OK) {
                fprintf(stderr, "curl_easy_pause() failed: %s\n", curl_easy_strerror(res));
            }
        }

        // Cleanup CURL
        curl_easy_cleanup(curl);
    }

    // Global cleanup
    curl_global_cleanup();

    return 0;
}