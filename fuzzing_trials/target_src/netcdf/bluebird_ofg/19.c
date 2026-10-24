#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_19(const uint8_t *data, size_t size) {
    // Ensure there's enough data to initialize all parameters
    if (size < sizeof(size_t) * 4 + sizeof(ptrdiff_t) * 2 + 2) {
        return 0;
    }

    // Initialize parameters
    int ncid = (int)data[0];
    int varid = (int)data[1];
    
    const size_t *start = (const size_t *)(data + 2);
    const size_t *count = (const size_t *)(data + 2 + sizeof(size_t));
    const ptrdiff_t *stride = (const ptrdiff_t *)(data + 2 + sizeof(size_t) * 2);
    const ptrdiff_t *imap = (const ptrdiff_t *)(data + 2 + sizeof(size_t) * 2 + sizeof(ptrdiff_t));

    // Allocate memory for the char array
    size_t char_array_size = size - (2 + sizeof(size_t) * 2 + sizeof(ptrdiff_t) * 2);
    char *value = (char *)malloc(char_array_size);
    if (value == NULL) {
        return 0;
    }
    memcpy(value, data + 2 + sizeof(size_t) * 2 + sizeof(ptrdiff_t) * 2, char_array_size);

    // Call the function-under-test
    int retval = nc_get_varm_text(ncid, varid, start, count, stride, imap, value);

    // Check for errors
    if (retval != NC_NOERR) {
        fprintf(stderr, "Error: %s\n", nc_strerror(retval));
        free(value);
        return 0;
    }

    // Clean up
    free(value);

    return 0;
}