#include <stdint.h>
#include <stddef.h>
#include <string.h> // Include this header for strlen
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_44(const uint8_t *data, size_t size) {
    // Ensure the size is at least 1 to read a byte for CURLMcode
    if (size < 1) {
        return 0;
    }

    // Use the first byte of the input data to create a CURLMcode value
    CURLMcode code = static_cast<CURLMcode>(data[0]);

    // Call the function-under-test
    const char *error_str = curl_multi_strerror(code);

    // Use the returned error string in some way to prevent optimization out
    if (error_str) {
        // Just a dummy operation to use the error_str
        volatile size_t len = strlen(error_str);
        (void)len;
    }

    return 0;
}