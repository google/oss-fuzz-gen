#include <gdbm.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_115(const uint8_t *data, size_t size) {
    // Ensure the data is null-terminated to be safely used as a C-string
    char *input = (char *)malloc(size + 1);
    if (!input) {
        return 0; // Exit if memory allocation fails
    }
    memcpy(input, data, size);
    input[size] = '\0';

    // Call the function-under-test
    gdbm_debug_token(input);

    // Free the allocated memory
    free(input);

    return 0;
}