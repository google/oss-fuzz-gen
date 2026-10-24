#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_37(const uint8_t *data, size_t size) {
    // Ensure the data is null-terminated before using it as a string
    char *inputString = static_cast<char*>(malloc(size + 1));
    if (inputString == nullptr) {
        return 0; // Memory allocation failed, return immediately
    }

    memcpy(inputString, data, size);
    inputString[size] = '\0'; // Null-terminate the string

    // Call the function-under-test
    curl_global_trace(inputString);

    // Free the allocated memory
    free(inputString);

    return 0;
}