#include <stdint.h>
#include <stddef.h>

// Function prototype for the function-under-test
int nc_put_var1_long(int ncid, int varid, const size_t *indexp, const long *op);

// Fuzzing harness
int LLVMFuzzerTestOneInput_218(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to extract required parameters
    if (size < sizeof(size_t) + sizeof(long)) {
        return 0;
    }

    // Initialize parameters for the function-under-test
    int ncid = 1; // Example non-zero value
    int varid = 1; // Example non-zero value

    // Extract size_t and long values from the data
    const size_t *indexp = (const size_t *)(data);
    const long *op = (const long *)(data + sizeof(size_t));

    // Call the function-under-test
    nc_put_var1_long(ncid, varid, indexp, op);

    return 0;
}