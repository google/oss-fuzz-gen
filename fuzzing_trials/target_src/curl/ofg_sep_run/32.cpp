#include <cstddef>
#include <cstdint>
#include <ctime>
#include <cstring>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_32(const uint8_t *data, size_t size) {
    // Ensure the data is null-terminated for string processing
    char *date_str = new char[size + 1];
    memcpy(date_str, data, size);
    date_str[size] = '\0';

    // Initialize a valid time_t value
    time_t now = time(nullptr);

    // Call the function-under-test
    time_t result = curl_getdate(date_str, &now);

    // Clean up
    delete[] date_str;

    return 0;
}