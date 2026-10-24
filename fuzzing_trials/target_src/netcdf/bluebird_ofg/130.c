#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern int nc_get_varm_uint(int ncid, int varid, const size_t *start, const size_t *count, const ptrdiff_t *stride, const ptrdiff_t *imap, unsigned int *value);

int LLVMFuzzerTestOneInput_130(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract parameters
    if (size < sizeof(size_t) * 2 + sizeof(ptrdiff_t) * 2 + sizeof(unsigned int)) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = (int)data[0];
    int varid = (int)data[1];

    size_t start[1];
    size_t count[1];
    ptrdiff_t stride[1];
    ptrdiff_t imap[1];
    unsigned int value;

    // Initialize the parameters
    memcpy(start, data + 2, sizeof(size_t));
    memcpy(count, data + 2 + sizeof(size_t), sizeof(size_t));
    memcpy(stride, data + 2 + sizeof(size_t) * 2, sizeof(ptrdiff_t));
    memcpy(imap, data + 2 + sizeof(size_t) * 2 + sizeof(ptrdiff_t), sizeof(ptrdiff_t));
    memcpy(&value, data + 2 + sizeof(size_t) * 2 + sizeof(ptrdiff_t) * 2, sizeof(unsigned int));

    // Call the function under test
    nc_get_varm_uint(ncid, varid, start, count, stride, imap, &value);

    return 0;
}