#include <gdbm.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput_64(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to extract a gdbm_error value
    if (size < sizeof(gdbm_error)) {
        return 0;
    }

    // Extract a gdbm_error value from the input data
    gdbm_error error_value;
    memcpy(&error_value, data, sizeof(gdbm_error));

    // Call the function-under-test
    gdbm_check_syserr(error_value);

    return 0;
}