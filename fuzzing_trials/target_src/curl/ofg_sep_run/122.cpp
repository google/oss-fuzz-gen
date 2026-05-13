#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdlib>

// Include the necessary C headers and ensure C linkage
extern "C" {
    #include <curl/curl.h>
}

// Define the LLVMFuzzerTestOneInput function
extern "C" int LLVMFuzzerTestOneInput_122(const uint8_t *data, size_t size) {
    // Ensure the data size is at least 2 to create two non-empty strings
    if (size < 2) {
        return 0;
    }

    // Divide the input data into two parts for the two strings
    size_t half_size = size / 2;

    // Allocate memory for the two strings and ensure they are null-terminated
    char *str1 = (char *)malloc(half_size + 1);
    char *str2 = (char *)malloc(size - half_size + 1);

    if (str1 == NULL || str2 == NULL) {
        free(str1);
        free(str2);
        return 0;
    }

    // Copy data into the strings and null-terminate them
    memcpy(str1, data, half_size);
    str1[half_size] = '\0';

    memcpy(str2, data + half_size, size - half_size);
    str2[size - half_size] = '\0';

    // Call the function-under-test
    int result = curl_strequal(str1, str2);

    // Free allocated memory
    free(str1);
    free(str2);

    // Return 0 as required by LLVMFuzzerTestOneInput
    return 0;
}