#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Assume the function variable_is_set is declared in a header file
int variable_is_set(const char *);

// Remove the extern "C" linkage specification for C++ and use C linkage
int LLVMFuzzerTestOneInput_58(const uint8_t *data, size_t size) {
    // Ensure the input data is null-terminated and non-empty
    if (size == 0) {
        return 0;
    }

    // Allocate memory for a null-terminated string
    char *inputString = (char *)malloc(size + 1);
    if (inputString == NULL) {
        return 0; // Allocation failed, exit
    }

    // Copy the data to the string and null-terminate it
    memcpy(inputString, data, size);
    inputString[size] = '\0';

    // Call the function-under-test
    variable_is_set(inputString);

    // Free the allocated memory
    free(inputString);

    return 0;
}