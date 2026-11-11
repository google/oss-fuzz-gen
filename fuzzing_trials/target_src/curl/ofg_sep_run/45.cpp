#include <stdint.h>
#include <stddef.h>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_45(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to extract a CURLMcode
    if (size < sizeof(CURLMcode)) {
        return 0;
    }

    // Extract a CURLMcode from the input data
    CURLMcode code = static_cast<CURLMcode>(data[0] % CURLM_LAST);

    // Call the function-under-test
    const char *error_str = curl_multi_strerror(code);

    // Use the error_str in some way to avoid compiler optimizations removing the call
    if (error_str != nullptr) {
        // Printing or logging can be done here if needed
    }

    return 0;
}