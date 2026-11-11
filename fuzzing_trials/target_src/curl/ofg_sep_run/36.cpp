#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_36(const uint8_t *data, size_t size) {
    // Ensure the data is null-terminated to be used as a string
    char *null_terminated_data = new char[size + 1];
    memcpy(null_terminated_data, data, size);
    null_terminated_data[size] = '\0';

    // Call the function-under-test
    CURLcode result = curl_global_trace(null_terminated_data);

    // Clean up allocated memory
    delete[] null_terminated_data;

    return 0;
}