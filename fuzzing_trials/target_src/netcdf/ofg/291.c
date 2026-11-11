#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Function signature for the function-under-test.
int nc_get_vars_uchar(int ncid, int varid, const size_t *start, const size_t *count, const ptrdiff_t *stride, unsigned char *value);

// Fuzzing harness for the function-under-test.
int LLVMFuzzerTestOneInput_291(const uint8_t *data, size_t size) {
    // Ensure there is enough data to initialize the parameters.
    if (size < sizeof(size_t) * 2 + sizeof(ptrdiff_t) + 1) {
        return 0;
    }

    // Initialize parameters for the function-under-test.
    int ncid = (int)data[0]; // Use the first byte for ncid
    int varid = (int)data[1]; // Use the second byte for varid

    // Use the next bytes for start and count arrays.
    const size_t *start = (const size_t *)(data + 2);
    const size_t *count = (const size_t *)(data + 2 + sizeof(size_t));

    // Use the next bytes for stride.
    const ptrdiff_t *stride = (const ptrdiff_t *)(data + 2 + sizeof(size_t) * 2);

    // Use the remaining byte for the value.
    unsigned char value = data[2 + sizeof(size_t) * 2 + sizeof(ptrdiff_t)];

    // Call the function-under-test.
    nc_get_vars_uchar(ncid, varid, start, count, stride, &value);

    return 0;
}