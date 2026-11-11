#include <cstdint>
#include <cstddef>
#include <cstring>
#include <iostream>

extern "C" {
    // Include the necessary header for the function-under-test
    #include "/src/liblouis/liblouis/liblouis.h"
}

extern "C" int LLVMFuzzerTestOneInput_40(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient to create two non-null strings
    if (size < 2) {
        return 0;
    }

    // Split the input data into two parts for the two string parameters
    size_t mid = size / 2;
    
    // Allocate memory for the two strings, ensuring null-termination
    char *str1 = new char[mid + 1];
    char *str2 = new char[size - mid + 1];

    // Copy the data into the strings and null-terminate them
    std::memcpy(str1, data, mid);
    str1[mid] = '\0';

    std::memcpy(str2, data + mid, size - mid);
    str2[size - mid] = '\0';

    // Call the function-under-test
    lou_compileString(str1, str2);

    // Clean up allocated memory
    delete[] str1;
    delete[] str2;

    return 0;
}