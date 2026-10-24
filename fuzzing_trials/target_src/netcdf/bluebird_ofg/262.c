#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

extern int nc_get_vara_long(int ncid, int varid, const size_t *start, const size_t *count, long *value);

int LLVMFuzzerTestOneInput_262(const uint8_t *data, size_t size) {
    if (size < 2 * sizeof(size_t) + sizeof(long)) {
        return 0;
    }

    int ncid = (int)data[0];
    int varid = (int)data[1];

    const size_t *start = (const size_t *)(data + 2);
    const size_t *count = (const size_t *)(data + 2 + sizeof(size_t));
    long *value = (long *)(data + 2 + 2 * sizeof(size_t));

    // Call the function-under-test
    nc_get_vara_long(ncid, varid, start, count, value);

    return 0;
}