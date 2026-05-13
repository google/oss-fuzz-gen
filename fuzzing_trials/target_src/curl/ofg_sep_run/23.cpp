#include <cstddef>
#include <cstdint>
#include <cstring>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_23(const uint8_t *data, size_t size) {
    // Ensure that the input size is not zero and does not exceed a reasonable limit
    if (size == 0 || size > 1024) {
        return 0;
    }

    // Allocate memory for the input string and ensure it's null-terminated
    char *input = new char[size + 1];
    memcpy(input, data, size);
    input[size] = '\0';

    // Call the function-under-test
    char *result = curl_unescape(input, static_cast<int>(size));

    // Clean up
    delete[] input;
    if (result != nullptr) {
        curl_free(result);
    }

    return 0;
}