#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Function-under-test declaration
void nmea_add_checksum(char *);

// Fuzzing harness
int LLVMFuzzerTestOneInput_15(const uint8_t *data, size_t size) {
    // Ensure there's enough space for the input and a null terminator
    if (size == 0) {
        return 0;
    }

    // Allocate memory for the input string with an additional space for the null terminator
    char *input = (char *)malloc(size + 1);
    if (input == NULL) {
        return 0; // If memory allocation fails, return immediately
    }

    // Copy the data into the input string and null terminate it
    memcpy(input, data, size);
    input[size] = '\0';

    // Call the function-under-test
    nmea_add_checksum(input);

    // Free the allocated memory
    free(input);

    return 0;
}