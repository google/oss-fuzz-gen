#include <gdbm.h>
#include <stdint.h>

// Function prototype for the fuzzer entry point
int LLVMFuzzerTestOneInput_63(const uint8_t *data, size_t size) {
    // Ensure that the size is at least the size of gdbm_error to extract a valid value
    if (size < sizeof(gdbm_error)) {
        return 0;
    }

    // Extract a gdbm_error value from the data
    gdbm_error error = *(gdbm_error *)data;

    // Call the function-under-test with the extracted gdbm_error value
    gdbm_check_syserr(error);

    return 0;
}