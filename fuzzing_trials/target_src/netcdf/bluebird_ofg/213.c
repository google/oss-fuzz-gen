#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_213(const uint8_t *data, size_t size) {
    if (size < sizeof(size_t) * 4 + sizeof(ptrdiff_t) * 2 + 1) {
        return 0; // Ensure there is enough data for the parameters
    }

    // Initialize parameters
    int ncid = 1; // Example non-zero file ID
    int varid = 1; // Example non-zero variable ID

    const size_t *start = (const size_t *)(data);
    const size_t *count = (const size_t *)(data + sizeof(size_t));
    const ptrdiff_t *stride = (const ptrdiff_t *)(data + 2 * sizeof(size_t));
    const ptrdiff_t *imap = (const ptrdiff_t *)(data + 2 * sizeof(size_t) + sizeof(ptrdiff_t));

    // Use remaining data as the buffer for the variable
    const void *buf = (const void *)(data + 2 * sizeof(size_t) + 2 * sizeof(ptrdiff_t));

    // Call the function-under-test
    int result = nc_put_varm(ncid, varid, start, count, stride, imap, buf);

    return 0;
}