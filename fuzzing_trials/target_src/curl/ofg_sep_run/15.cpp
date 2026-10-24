#include <stdint.h>
#include <stddef.h>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_15(const uint8_t *data, size_t size) {
    // Ensure that the data is large enough to extract a CURLUcode value
    if (size < sizeof(CURLUcode)) {
        return 0;
    }

    // Extract a CURLUcode value from the input data
    CURLUcode code = static_cast<CURLUcode>(data[0]);

    // Call the function-under-test
    const char *errorStr = curl_url_strerror(code);

    // Use the returned error string (for example, print it)
    // In a real fuzzing scenario, you might not print it to avoid cluttering the output
    // printf("Error String: %s\n", errorStr);

    return 0;
}