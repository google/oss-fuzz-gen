#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern int nc_get_varm_schar(int ncid, int varid, const size_t *start, const size_t *count, const ptrdiff_t *stride, const ptrdiff_t *imap, signed char *value);

int LLVMFuzzerTestOneInput_132(const uint8_t *data, size_t size) {
    if (size < sizeof(size_t) * 2 + sizeof(ptrdiff_t) * 2 + sizeof(signed char)) {
        return 0;
    }

    // Initialize variables
    int ncid = 1;  // Example non-zero value
    int varid = 1; // Example non-zero value

    // Pointers to the data
    const size_t *start = (const size_t *)data;
    const size_t *count = (const size_t *)(data + sizeof(size_t));
    const ptrdiff_t *stride = (const ptrdiff_t *)(data + sizeof(size_t) * 2);
    const ptrdiff_t *imap = (const ptrdiff_t *)(data + sizeof(size_t) * 2 + sizeof(ptrdiff_t));
    signed char *value = (signed char *)(data + sizeof(size_t) * 2 + sizeof(ptrdiff_t) * 2);

    // Call the function-under-test
    nc_get_varm_schar(ncid, varid, start, count, stride, imap, value);

    return 0;
}