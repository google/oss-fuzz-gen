#include <cstdlib>
#include <cstdint>
#include <cstring>

extern "C" {
    #include "/src/liblouis/liblouis/liblouis.h"
}

extern "C" int LLVMFuzzerTestOneInput_41(const uint8_t *data, size_t size) {
    // Ensure the input data is not empty
    if (size == 0) {
        return 0;
    }

    // Create two null-terminated strings from the input data
    size_t half_size = size / 2;
    
    // Allocate memory for the strings
    char *str1 = (char *)malloc(half_size + 1);
    char *str2 = (char *)malloc(size - half_size + 1);

    // Ensure memory allocation was successful
    if (str1 == nullptr || str2 == nullptr) {
        free(str1);
        free(str2);
        return 0;
    }

    // Copy data into the strings and null-terminate them
    memcpy(str1, data, half_size);
    str1[half_size] = '\0';

    memcpy(str2, data + half_size, size - half_size);
    str2[size - half_size] = '\0';

    // Call the function under test
    lou_compileString(str1, str2);

    // Free allocated memory
    free(str1);
    free(str2);

    return 0;
}