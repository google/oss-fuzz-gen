#include <curl/curl.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_107(const uint8_t *data, size_t size) {
    // Initialize CURL
    CURL *curl = curl_easy_init();
    if (!curl) {
        return 0;
    }

    // Ensure the input is null-terminated
    char *input = (char *)malloc(size + 1);
    if (!input) {
        curl_easy_cleanup(curl);
        return 0;
    }
    memcpy(input, data, size);
    input[size] = '\0';

    // Use a non-zero integer for the length parameter
    int length = static_cast<int>(size);

    // Call the function-under-test
    char *escaped_str = curl_easy_escape(curl, input, length);

    // Clean up
    if (escaped_str) {
        curl_free(escaped_str);
    }
    free(input);
    curl_easy_cleanup(curl);

    return 0;
}