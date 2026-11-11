#include <curl/curl.h>
#include <stdint.h>
#include <stddef.h>

extern "C" int LLVMFuzzerTestOneInput_97(const uint8_t *data, size_t size) {
    CURLM *multi_handle;
    CURLMcode result;
    CURLMoption options[] = {
        CURLMOPT_PIPELINING,
        CURLMOPT_MAXCONNECTS,
        CURLMOPT_MAX_HOST_CONNECTIONS,
        CURLMOPT_MAX_PIPELINE_LENGTH,
        CURLMOPT_MAX_TOTAL_CONNECTIONS
    };

    // Initialize a multi handle
    multi_handle = curl_multi_init();
    if (!multi_handle) {
        return 0;
    }

    // Ensure size is non-zero to avoid division by zero
    if (size == 0) {
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Use the first byte of data to determine the option index
    size_t option_index = data[0] % (sizeof(options) / sizeof(CURLMoption));

    // Use the second byte of data as a value, if available
    long value = (size > 1) ? static_cast<long>(data[1]) : 1;

    // Set the option with the selected value
    result = curl_multi_setopt(multi_handle, options[option_index], (void *)value);

    // Cleanup
    curl_multi_cleanup(multi_handle);

    return 0;
}