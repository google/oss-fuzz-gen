#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Assume command_generator is declared somewhere
char * command_generator(const char *, int);

int LLVMFuzzerTestOneInput_99(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for the function parameters
    if (size < 2) {
        return 0;
    }

    // Create a null-terminated string from the data
    char *input_str = (char *)malloc(size + 1);
    if (!input_str) {
        return 0;
    }
    memcpy(input_str, data, size);
    input_str[size] = '\0';

    // Use the first byte of data as an integer parameter
    int int_param = (int)data[0];

    // Call the function-under-test
    char *result = command_generator(input_str, int_param);

    // Free the result if it was dynamically allocated
    free(result);

    // Clean up
    free(input_str);

    return 0;
}