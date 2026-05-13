#include <cstddef>
#include <cstdint>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_56(const uint8_t *data, size_t size) {
    // Ensure that the size is non-zero to avoid accessing out of bounds
    if (size == 0) {
        return 0;
    }

    // Use the first byte of data to determine the CURLSHcode value
    CURLSHcode code = static_cast<CURLSHcode>(data[0] % (CURLSHE_LAST + 1));

    // Call the function-under-test
    const char *error_str = curl_share_strerror(code);

    // Use the error_str in some way to prevent compiler optimizations removing the call
    // Here, we simply check if it's non-null
    if (error_str != nullptr) {
        // Do something trivial with error_str
        volatile char c = error_str[0];
        (void)c; // Suppress unused variable warning
    }

    return 0;
}