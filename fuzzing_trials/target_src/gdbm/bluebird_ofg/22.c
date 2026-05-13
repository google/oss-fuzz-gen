#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>

// Function-under-test
char *command_generator(const char *, int);

int LLVMFuzzerTestOneInput_22(const uint8_t *data, size_t size) {
    // Ensure that size is non-zero for valid string and integer value
    if (size < 2) {
        return 0;
    }

    // Allocate memory for the string input
    char *inputString = (char *)malloc(size + 1);
    if (!inputString) {
        return 0;
    }

    // Copy data to inputString and null-terminate it
    memcpy(inputString, data, size);
    inputString[size] = '\0';

    // Use the first byte of data as an integer input
    int intValue = (int)data[0];

    // Call the function-under-test
    char *result = command_generator(inputString, intValue);

    // Free the result if it's not NULL
    if (result) {
        free(result);
    }

    // Free allocated memory for inputString
    free(inputString);

    return 0;
}