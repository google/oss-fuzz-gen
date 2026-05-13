#include <stdint.h>
#include <stddef.h>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_57(const uint8_t *data, size_t size) {
    // Ensure there is at least one byte to read
    if (size < 1) {
        return 0;
    }

    // Use the first byte of data to determine the CURLSHcode
    CURLSHcode code = static_cast<CURLSHcode>(data[0] % CURLSHE_LAST);

    // Call the function-under-test
    const char *error_str = curl_share_strerror(code);

    // Optionally, you can do something with the result, like printing
    // but for fuzzing purposes, just calling the function is enough
    (void)error_str; // Suppress unused variable warning

    return 0;
}