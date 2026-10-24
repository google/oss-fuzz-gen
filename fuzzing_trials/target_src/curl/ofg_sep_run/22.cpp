#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_22(const uint8_t *data, size_t size) {
    // Ensure that the input data is not empty
    if (size == 0) {
        return 0;
    }

    // Allocate memory for the input string and ensure it's null-terminated
    char *input = (char *)malloc(size + 1);
    if (input == NULL) {
        return 0;
    }
    memcpy(input, data, size);
    input[size] = '\0';

    // Call the function-under-test
    char *result = curl_unescape(input, static_cast<int>(size));

    // Free the allocated memory
    free(input);

    // Free the result from curl_unescape if it's not NULL
    if (result != NULL) {
        curl_free(result);
    }

    return 0;
}