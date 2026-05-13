#include <stddef.h>
#include <stdint.h>
#include <string.h>  // Include string.h for memcpy

extern int nc_put_varm_float(int ncid, int varid, const size_t *start, const size_t *count, const ptrdiff_t *stride, const ptrdiff_t *imap, const float *fp);

int LLVMFuzzerTestOneInput_142(const uint8_t *data, size_t size) {
    if (size < sizeof(size_t) * 2 + sizeof(ptrdiff_t) * 2 + sizeof(float)) {
        return 0;
    }

    int ncid = 0;  // Example value, should be set appropriately
    int varid = 0; // Example value, should be set appropriately

    size_t start[2];
    size_t count[2];
    ptrdiff_t stride[2];
    ptrdiff_t imap[2];
    float fp[1];

    // Ensure the data buffer is large enough to fill the arrays
    if (size < sizeof(start) + sizeof(count) + sizeof(stride) + sizeof(imap) + sizeof(fp)) {
        return 0;
    }

    // Initialize start, count, stride, imap, and fp with data from the input buffer
    memcpy(start, data, sizeof(start));
    memcpy(count, data + sizeof(start), sizeof(count));
    memcpy(stride, data + sizeof(start) + sizeof(count), sizeof(stride));
    memcpy(imap, data + sizeof(start) + sizeof(count) + sizeof(stride), sizeof(imap));
    memcpy(fp, data + sizeof(start) + sizeof(count) + sizeof(stride) + sizeof(imap), sizeof(fp));

    // Call the function-under-test
    nc_put_varm_float(ncid, varid, start, count, stride, imap, fp);

    return 0;
}