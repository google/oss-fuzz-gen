#include <gdbm.h>
#include <stdint.h>
#include <stdio.h>

int LLVMFuzzerTestOneInput_59(const uint8_t *data, size_t size) {
    // Ensure that size is large enough to extract a gdbm_error value
    if (size < sizeof(gdbm_error)) {
        return 0;
    }

    // Extract gdbm_error from the data
    gdbm_error error_code = *(gdbm_error *)data;

    // Call the function-under-test
    const char *error_message = gdbm_strerror(error_code);

    // Print the error message (for debugging purposes)
    printf("Error message: %s\n", error_message);

    return 0;
}