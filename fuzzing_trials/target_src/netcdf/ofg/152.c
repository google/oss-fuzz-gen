#include <stdint.h>
#include <stddef.h>

// Function prototype for the function-under-test
int nc_get_var_uint(int ncid, int varid, unsigned int *ip);

// Fuzzing harness
int LLVMFuzzerTestOneInput_152(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to extract integers
    if (size < sizeof(int) * 2 + sizeof(unsigned int)) {
        return 0;
    }

    // Extract integers from the input data
    int ncid = *(const int *)data;
    int varid = *(const int *)(data + sizeof(int));
    unsigned int ip;

    // Call the function-under-test
    int result = nc_get_var_uint(ncid, varid, &ip);

    // Use the result and ip in some way to prevent compiler optimizations from removing the call
    (void)result;
    (void)ip;

    return 0;
}