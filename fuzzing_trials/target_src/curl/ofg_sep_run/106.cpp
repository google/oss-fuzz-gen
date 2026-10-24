#include <cstdint>
#include <cstdlib>
#include <cstring> // Include for memcpy
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_106(const uint8_t *data, size_t size) {
    // Initialize CURL
    CURL *curl = curl_easy_init();
    if (!curl) {
        return 0;
    }

    // Ensure the input data is null-terminated
    char *input = static_cast<char *>(malloc(size + 1));
    if (!input) {
        curl_easy_cleanup(curl);
        return 0;
    }
    memcpy(input, data, size);
    input[size] = '\0';

    // Call the function-under-test
    char *escaped = curl_easy_escape(curl, input, static_cast<int>(size));

    // Cleanup
    if (escaped) {
        curl_free(escaped);
    }
    free(input);
    curl_easy_cleanup(curl);

    return 0;
}