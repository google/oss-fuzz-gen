#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

extern int nc_get_varm_double(int ncid, int varid, const size_t *start, const size_t *count, const ptrdiff_t *stride, const ptrdiff_t *imap, double *data);

int LLVMFuzzerTestOneInput_187(const uint8_t *data, size_t size) {
    if (size < 2 * sizeof(int) + 4 * sizeof(size_t) + 4 * sizeof(ptrdiff_t) + sizeof(double)) {
        return 0;
    }

    int ncid = *((int *)data);
    int varid = *((int *)(data + sizeof(int)));

    size_t start[2];
    size_t count[2];
    ptrdiff_t stride[2];
    ptrdiff_t imap[2];
    double data_out[1];

    start[0] = *((size_t *)(data + 2 * sizeof(int)));
    start[1] = *((size_t *)(data + 2 * sizeof(int) + sizeof(size_t)));
    count[0] = *((size_t *)(data + 2 * sizeof(int) + 2 * sizeof(size_t)));
    count[1] = *((size_t *)(data + 2 * sizeof(int) + 3 * sizeof(size_t)));
    stride[0] = *((ptrdiff_t *)(data + 2 * sizeof(int) + 4 * sizeof(size_t)));
    stride[1] = *((ptrdiff_t *)(data + 2 * sizeof(int) + 4 * sizeof(size_t) + sizeof(ptrdiff_t)));
    imap[0] = *((ptrdiff_t *)(data + 2 * sizeof(int) + 4 * sizeof(size_t) + 2 * sizeof(ptrdiff_t)));
    imap[1] = *((ptrdiff_t *)(data + 2 * sizeof(int) + 4 * sizeof(size_t) + 3 * sizeof(ptrdiff_t)));

    nc_get_varm_double(ncid, varid, start, count, stride, imap, data_out);

    return 0;
}