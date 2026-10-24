#include <cstdint>
#include <cstddef>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_30(const uint8_t *data, size_t size) {
    // Ensure there is at least one byte to interpret as CURLcode
    if (size < 1) {
        return 0;
    }

    // Interpret the first byte of data as a CURLcode
    CURLcode code = static_cast<CURLcode>(data[0]);

    // Call the function-under-test
    const char *error_message = curl_easy_strerror(code);

    // Use the error_message in some way to avoid compiler optimizations
    if (error_message != nullptr) {
        // For the sake of the fuzzer, we don't need to do anything with the message
    }

    return 0;
}