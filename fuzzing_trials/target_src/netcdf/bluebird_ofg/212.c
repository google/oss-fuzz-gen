#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Assuming nc_get_varm_short is part of a library that needs to be linked during compilation
extern int nc_get_varm_short(int ncid, int varid, const size_t *start, const size_t *count, const ptrdiff_t *stride, const ptrdiff_t *imap, short *value);

int LLVMFuzzerTestOneInput_212(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    int ncid = 1; // Example non-zero value for ncid
    int varid = 1; // Example non-zero value for varid

    // Define the required size for the input data
    size_t required_size = 2 * sizeof(size_t) + 2 * sizeof(size_t) + 2 * sizeof(ptrdiff_t) + 2 * sizeof(ptrdiff_t) + sizeof(short);

    // Ensure size is large enough to extract necessary values
    if (size < required_size) {
        return 0;
    }

    // Initialize start and count arrays with non-zero values
    size_t start[2];
    size_t count[2];
    memcpy(start, data, sizeof(size_t) * 2);
    memcpy(count, data + sizeof(size_t) * 2, sizeof(size_t) * 2);

    // Ensure start and count are non-zero to make the function call meaningful
    for (int i = 0; i < 2; i++) {
        if (start[i] == 0) start[i] = 1;
        if (count[i] == 0) count[i] = 1;
    }

    // Initialize stride and imap arrays with non-zero values
    ptrdiff_t stride[2];
    ptrdiff_t imap[2];
    memcpy(stride, data + sizeof(size_t) * 4, sizeof(ptrdiff_t) * 2);
    memcpy(imap, data + sizeof(size_t) * 4 + sizeof(ptrdiff_t) * 2, sizeof(ptrdiff_t) * 2);

    // Ensure stride and imap are non-zero to make the function call meaningful
    for (int i = 0; i < 2; i++) {
        if (stride[i] == 0) stride[i] = 1;
        if (imap[i] == 0) imap[i] = 1;
    }

    // Initialize value array with a non-zero value
    short value[1];
    memcpy(value, data + sizeof(size_t) * 4 + sizeof(ptrdiff_t) * 4, sizeof(short));
    if (value[0] == 0) value[0] = 1;

    // Call the function-under-test
    nc_get_varm_short(ncid, varid, start, count, stride, imap, value);

    return 0;
}