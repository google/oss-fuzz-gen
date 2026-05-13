#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h> // Include string.h for memset

extern int nc_get_varm_uchar(int ncid, int varid, const size_t *start, const size_t *count, const ptrdiff_t *stride, const ptrdiff_t *imap, unsigned char *value);

int LLVMFuzzerTestOneInput_406(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for all the data we need
    if (size < 2 + 2 * sizeof(size_t) + 2 * sizeof(ptrdiff_t) + sizeof(unsigned char)) {
        return 0;
    }

    // Extract ncid and varid from the data
    int ncid = (int)data[0];
    int varid = (int)data[1];

    // Allocate memory for start, count, stride, imap, and value
    size_t start[1];
    size_t count[1];
    ptrdiff_t stride[1];
    ptrdiff_t imap[1];
    unsigned char value[1];

    // Copy data into these variables
    memcpy(start, data + 2, sizeof(size_t));
    memcpy(count, data + 2 + sizeof(size_t), sizeof(size_t));
    memcpy(stride, data + 2 + 2 * sizeof(size_t), sizeof(ptrdiff_t));
    memcpy(imap, data + 2 + 2 * sizeof(size_t) + sizeof(ptrdiff_t), sizeof(ptrdiff_t));
    memcpy(value, data + 2 + 2 * sizeof(size_t) + 2 * sizeof(ptrdiff_t), sizeof(unsigned char));

    // Call the function under test
    int result = nc_get_varm_uchar(ncid, varid, start, count, stride, imap, value);

    // Return 0 as required by the fuzzer
    return 0;
}