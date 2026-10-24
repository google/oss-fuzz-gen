#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Function-under-test declaration
int getnum(int *, char *, char **);

int LLVMFuzzerTestOneInput_173(const uint8_t *data, size_t size) {
    // Ensure there's enough data to initialize parameters
    if (size < sizeof(int) + 2) {
        return 0;
    }

    // Initialize the integer parameter
    int num = *((int *)data);

    // Initialize the char* parameter
    char *str = (char *)(data + sizeof(int));

    // Ensure null-termination for the string
    size_t str_size = size - sizeof(int);
    char *str_copy = (char *)malloc(str_size + 1);
    if (!str_copy) {
        return 0; // Memory allocation failed
    }
    memcpy(str_copy, str, str_size);
    str_copy[str_size] = '\0';

    // Initialize the char** parameter
    char *endptr = NULL;

    // Call the function-under-test
    getnum(&num, str_copy, &endptr);

    // Free allocated memory
    free(str_copy);

    return 0;
}