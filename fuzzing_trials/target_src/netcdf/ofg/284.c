#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

extern int nc_get_varm_long(int ncid, int varid, const size_t *start, const size_t *count, const ptrdiff_t *stride, const ptrdiff_t *imap, long *value);

int LLVMFuzzerTestOneInput_284(const uint8_t *data, size_t size) {
    if (size < 6 * sizeof(size_t) + 2 * sizeof(ptrdiff_t) + sizeof(long)) {
        return 0;
    }

    int ncid = (int)data[0];
    int varid = (int)data[1];

    const size_t *start = (const size_t *)(data + 2);
    const size_t *count = (const size_t *)(data + 2 + sizeof(size_t));
    const ptrdiff_t *stride = (const ptrdiff_t *)(data + 2 + 2 * sizeof(size_t));
    const ptrdiff_t *imap = (const ptrdiff_t *)(data + 2 + 2 * sizeof(size_t) + sizeof(ptrdiff_t));
    long *value = (long *)(data + 2 + 2 * sizeof(size_t) + 2 * sizeof(ptrdiff_t));

    // Ensure that arrays are non-NULL and have at least one element
    size_t start_array[1] = {start[0]};
    size_t count_array[1] = {count[0]};
    ptrdiff_t stride_array[1] = {stride[0]};
    ptrdiff_t imap_array[1] = {imap[0]};
    long value_array[1] = {value[0]};

    nc_get_varm_long(ncid, varid, start_array, count_array, stride_array, imap_array, value_array);

    return 0;
}