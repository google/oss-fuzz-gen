#include <gdbm.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h> // Include this for memcpy

int LLVMFuzzerTestOneInput_60(const uint8_t *data, size_t size) {
    // Ensure that size is sufficient to extract an integer
    if (size < sizeof(int)) {
        return 0;
    }

    // Extract an integer from the input data
    int gdbm_error_code;
    memcpy(&gdbm_error_code, data, sizeof(int));

    // Call the function-under-test
    const char *error_message = gdbm_strerror((gdbm_error)gdbm_error_code);

    // Print the error message for debugging purposes
    printf("GDBM Error Code: %d, Message: %s\n", gdbm_error_code, error_message);

    return 0;
}