#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h> // Include for malloc and free

// Assuming the definition of `str` type is as follows:
typedef struct {
    char *data;
    size_t length;
} str;

// Function-under-test
int normalize_tel_user(char *input, str *output);

int LLVMFuzzerTestOneInput_24(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0; // Need at least space for one char and null terminator
    }

    // Allocate memory for input string and ensure it is null-terminated
    char *input = (char *)malloc(size + 1);
    if (input == NULL) {
        return 0; // Allocation failed
    }
    memcpy(input, data, size);
    input[size] = '\0'; // Null-terminate the input string

    // Prepare the output structure
    str output;
    output.data = (char *)malloc(size + 1); // Allocate enough space
    if (output.data == NULL) {
        free(input);
        return 0; // Allocation failed
    }
    output.length = size;

    // Call the function-under-test
    normalize_tel_user(input, &output);

    // Free allocated memory
    free(input);
    free(output.data);

    return 0;
}