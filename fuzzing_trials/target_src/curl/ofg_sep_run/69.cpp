#include <curl/curl.h>
#include <cstddef>
#include <cstdint>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_69(const uint8_t *data, size_t size) {
    CURL *curl;
    char *unescaped;
    int outlength;

    // Initialize a CURL easy handle
    curl = curl_easy_init();
    if (!curl) {
        return 0;
    }

    // Ensure the input data is null-terminated for the function
    char *input = new char[size + 1];
    memcpy(input, data, size);
    input[size] = '\0';

    // Call the function-under-test
    unescaped = curl_easy_unescape(curl, input, static_cast<int>(size), &outlength);

    // Clean up
    if (unescaped) {
        curl_free(unescaped);
    }
    delete[] input;
    curl_easy_cleanup(curl);

    return 0;
}