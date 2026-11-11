#include <cstddef>
#include <cstdint>
#include <cstring>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_103(const uint8_t *data, size_t size) {
    // Ensure the input size is non-zero and within a reasonable limit
    if (size == 0 || size > 1024) {
        return 0;
    }

    // Copy the data into a null-terminated string
    char *input = new char[size + 1];
    std::memcpy(input, data, size);
    input[size] = '\0';

    // Call the function-under-test
    char *escaped = curl_escape(input, static_cast<int>(size));

    // Clean up
    if (escaped != nullptr) {
        curl_free(escaped);
    }
    delete[] input;

    return 0;
}