#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Function prototype for the function-under-test
char *nc_rc_get(const char *);

int LLVMFuzzerTestOneInput_314(const uint8_t *data, size_t size) {
    // Ensure the data is null-terminated and not empty
    if (size == 0) {
        return 0;
    }

    // Allocate memory for the input string and ensure it is null-terminated
    char *input = (char *)malloc(size + 1);
    if (input == NULL) {
        return 0;
    }
    memcpy(input, data, size);
    input[size] = '\0';

    // Call the function-under-test
    char *result = nc_rc_get(input);

    // Free the allocated input string
    free(input);

    // Free the result if it's dynamically allocated and not NULL
    if (result != NULL) {
        free(result);
    }

    return 0;
}