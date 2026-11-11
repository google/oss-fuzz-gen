#include <curl/curl.h>
#include <stdint.h>
#include <stddef.h>

extern "C" int LLVMFuzzerTestOneInput_110(const uint8_t *data, size_t size) {
    // Ensure that the data size is sufficient to extract a long value
    if (size < sizeof(long)) {
        return 0;
    }

    // Extract a long value from the input data
    long init_flags = 0;
    for (size_t i = 0; i < sizeof(long); ++i) {
        init_flags = (init_flags << 8) | data[i];
    }

    // Call the function-under-test
    CURLcode result = curl_global_init(init_flags);

    // Optionally, handle the result if needed
    // For example, you could log the result or perform additional checks

    // Clean up if necessary (not needed for curl_global_init)
    // curl_global_cleanup(); // Uncomment if you want to clean up after testing

    return 0;
}