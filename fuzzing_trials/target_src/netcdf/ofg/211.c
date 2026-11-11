#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern int nc_get_vars_ushort(int ncid, int varid, const size_t *start, const size_t *count, const ptrdiff_t *stride, unsigned short *data);

int LLVMFuzzerTestOneInput_211(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract parameters
    if (size < sizeof(int) * 2 + sizeof(size_t) * 2 + sizeof(ptrdiff_t) + sizeof(unsigned short)) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *((int *)data);
    data += sizeof(int);
    size -= sizeof(int);

    int varid = *((int *)data);
    data += sizeof(int);
    size -= sizeof(int);

    size_t start[1];
    start[0] = *((size_t *)data);
    data += sizeof(size_t);
    size -= sizeof(size_t);

    size_t count[1];
    count[0] = *((size_t *)data);
    data += sizeof(size_t);
    size -= sizeof(size_t);

    ptrdiff_t stride[1];
    stride[0] = *((ptrdiff_t *)data);
    data += sizeof(ptrdiff_t);
    size -= sizeof(ptrdiff_t);

    unsigned short *output_data = (unsigned short *)malloc(sizeof(unsigned short) * count[0]);
    if (output_data == NULL) {
        return 0;
    }

    // Call the function-under-test
    int result = nc_get_vars_ushort(ncid, varid, start, count, stride, output_data);

    // Clean up
    free(output_data);

    return 0;
}