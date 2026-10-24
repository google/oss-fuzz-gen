#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_176(const uint8_t *data, size_t size) {
    // Check if the size is sufficient to extract required parameters
    if (size < sizeof(int) * 2 + sizeof(size_t) * 2 + sizeof(long)) {
        return 0;
    }

    // Initialize parameters
    int ncid = *(const int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    int varid = *(const int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    size_t start[1];
    start[0] = *(const size_t *)data;
    data += sizeof(size_t);
    size -= sizeof(size_t);

    size_t count[1];
    count[0] = *(const size_t *)data;
    data += sizeof(size_t);
    size -= sizeof(size_t);

    // Ensure count is non-zero to avoid undefined behavior
    if (count[0] == 0) {
        count[0] = 1;
    }

    // Allocate memory for the long array
    long *values = (long *)malloc(count[0] * sizeof(long));
    if (values == NULL) {
        return 0;
    }

    // Fill the long array with data
    for (size_t i = 0; i < count[0]; i++) {
        if (size < sizeof(long)) {
            values[i] = 0; // Default value if not enough data
        } else {
            values[i] = *(const long *)data;
            data += sizeof(long);
            size -= sizeof(long);
        }
    }

    // Call the function-under-test
    nc_put_vara_long(ncid, varid, start, count, values);

    // Free allocated memory
    free(values);

    return 0;
}