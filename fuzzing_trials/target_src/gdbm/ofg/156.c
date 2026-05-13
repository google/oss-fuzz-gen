#include <gdbm.h>
#include <stdint.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput_156(const uint8_t *data, size_t size) {
    // Call the function-under-test
    int *errno_location = gdbm_errno_location();

    // Use the returned pointer in some way to ensure the function is actually called
    // For example, set it to a known error code
    if (errno_location != NULL) {
        *errno_location = GDBM_NO_ERROR; // Set to a known error code
    }

    return 0;
}