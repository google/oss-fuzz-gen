#include <cstdint>
#include <cstddef>
#include <cstring>

// Include the appropriate header for the function
extern "C" {
    #include "/src/liblouis/liblouis/liblouis.h"
}

// Fuzzing harness
extern "C" int LLVMFuzzerTestOneInput_32(const uint8_t *data, size_t size) {
    // Ensure there is enough data to create two non-null strings
    if (size < 2) {
        return 0;
    }

    // Split the data into two parts for the two string parameters
    size_t mid = size / 2;

    // Allocate memory for the two strings and null-terminate them
    char *str1 = new char[mid + 1];
    char *str2 = new char[size - mid + 1];

    // Copy data into the strings and null-terminate
    memcpy(str1, data, mid);
    str1[mid] = '\0';

    memcpy(str2, data + mid, size - mid);
    str2[size - mid] = '\0';

    // Call the function under test
    formtype result = lou_getTypeformForEmphClass(str1, str2);

    // Clean up
    delete[] str1;
    delete[] str2;

    return 0;
}