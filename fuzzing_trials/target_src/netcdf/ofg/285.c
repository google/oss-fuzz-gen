#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

extern int nc_get_varm_long(int ncid, int varid, const size_t *start, const size_t *count, const ptrdiff_t *stride, const ptrdiff_t *imap, long *data);

int LLVMFuzzerTestOneInput_285(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract parameters
    if (size < sizeof(int) * 2 + sizeof(size_t) * 2 + sizeof(ptrdiff_t) * 2 + sizeof(long)) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *(const int *)data;
    int varid = *(const int *)(data + sizeof(int));

    const size_t *start = (const size_t *)(data + 2 * sizeof(int));
    const size_t *count = (const size_t *)(data + 2 * sizeof(int) + sizeof(size_t));

    const ptrdiff_t *stride = (const ptrdiff_t *)(data + 2 * sizeof(int) + 2 * sizeof(size_t));
    const ptrdiff_t *imap = (const ptrdiff_t *)(data + 2 * sizeof(int) + 2 * sizeof(size_t) + sizeof(ptrdiff_t));

    long *output_data = (long *)(data + 2 * sizeof(int) + 2 * sizeof(size_t) + 2 * sizeof(ptrdiff_t));

    // Call the function-under-test
    nc_get_varm_long(ncid, varid, start, count, stride, imap, output_data);

    return 0;
}