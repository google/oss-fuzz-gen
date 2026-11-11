#include <curl/curl.h>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput_68(const uint8_t *data, size_t size) {
    // Initialize CURL
    CURL *curl = curl_easy_init();
    if (!curl) {
        return 0;
    }

    // Ensure the input data is null-terminated
    char *input_data = (char *)malloc(size + 1);
    if (!input_data) {
        curl_easy_cleanup(curl);
        return 0;
    }
    memcpy(input_data, data, size);
    input_data[size] = '\0';

    // Prepare the output length pointer
    int output_length = 0;

    // Call the function under test
    char *unescaped = curl_easy_unescape(curl, input_data, static_cast<int>(size), &output_length);

    // Cleanup
    if (unescaped) {
        curl_free(unescaped);
    }
    free(input_data);
    curl_easy_cleanup(curl);

    return 0;
}