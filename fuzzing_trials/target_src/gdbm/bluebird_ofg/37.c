#include "/src/gdbm/src/gdbm.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>

extern int gdbm_debug_token(const char *);

int LLVMFuzzerTestOneInput_37(const uint8_t *data, size_t size) {
    // Ensure the input data is null-terminated to be used as a string
    char *input = (char *)malloc(size + 1);
    if (!input) {
        return 0; // Exit gracefully if memory allocation fails
    }
    
    memcpy(input, data, size);
    input[size] = '\0'; // Null-terminate the string

    // Call the function-under-test with the input string
    gdbm_debug_token(input);

    // Free the allocated memory
    free(input);

    return 0;
}