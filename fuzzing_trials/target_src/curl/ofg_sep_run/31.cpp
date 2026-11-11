#include <stdint.h>
#include <stddef.h>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_31(const uint8_t *data, size_t size) {
    // Ensure the input size is at least the size of a CURLcode
    if (size < sizeof(CURLcode)) {
        return 0;
    }

    // Interpret the first bytes of data as a CURLcode
    CURLcode code = static_cast<CURLcode>(data[0]);

    // Call the function-under-test
    const char *error_str = curl_easy_strerror(code);

    // Use the result to prevent any compiler optimizations that might skip the function call
    if (error_str != NULL) {
        // Do something trivial with error_str, like checking its length
        size_t len = 0;
        while (error_str[len] != '\0') {
            len++;
        }
    }

    return 0;
}