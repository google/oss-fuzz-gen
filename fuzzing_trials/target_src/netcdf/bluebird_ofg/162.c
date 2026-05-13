#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Function prototype for the function-under-test
int nc_put_vars_ulonglong(int ncid, int varid, const size_t *start, const size_t *count, const ptrdiff_t *stride, const unsigned long long *data);

int LLVMFuzzerTestOneInput_162(const uint8_t *data, size_t size) {
    // Declare and initialize the parameters for the function-under-test
    int ncid = 1;  // Example non-zero ncid
    int varid = 1; // Example non-zero varid

    // Ensure size is sufficient for at least one element in each array
    if (size < sizeof(size_t) * 3 + sizeof(ptrdiff_t) + sizeof(unsigned long long)) {
        return 0;
    }

    // Initialize start, count, and stride arrays
    size_t start[1];
    size_t count[1];
    ptrdiff_t stride[1];
    unsigned long long values[1];

    // Copy data into arrays ensuring they are not zero
    memcpy(start, data, sizeof(size_t));
    memcpy(count, data + sizeof(size_t), sizeof(size_t));
    memcpy(stride, data + 2 * sizeof(size_t), sizeof(ptrdiff_t));
    memcpy(values, data + 2 * sizeof(size_t) + sizeof(ptrdiff_t), sizeof(unsigned long long));

    // Ensure non-zero values for meaningful execution
    if (*start == 0) *start = 1;
    if (*count == 0) *count = 1;
    if (*stride == 0) *stride = 1;
    if (*values == 0) *values = 1;

    // Call the function-under-test
    nc_put_vars_ulonglong(ncid, varid, start, count, stride, values);

    return 0;
}