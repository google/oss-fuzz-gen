#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

// Assuming the function is declared in a header file
#include "netcdf.h"

int LLVMFuzzerTestOneInput_361(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    int ncid = 1;  // Example non-zero integer, assuming valid file ID
    int varid = 1; // Example non-zero integer, assuming valid variable ID
    int attnum = 1; // Example non-zero integer, assuming valid attribute number

    // Ensure the size is large enough for a string
    if (size < 1) {
        return 0;
    }

    // Allocate memory for the attribute name
    char attname[256];
    memset(attname, 0, sizeof(attname));

    // Copy data to attname ensuring it is null-terminated
    size_t copy_size = size < sizeof(attname) - 1 ? size : sizeof(attname) - 1;
    memcpy(attname, data, copy_size);
    attname[copy_size] = '\0';

    // Call the function-under-test
    int retval = nc_inq_attname(ncid, varid, attnum, attname);

    // Check the return value to ensure the function is invoked correctly
    if (retval != NC_NOERR) {
        fprintf(stderr, "nc_inq_attname failed with error code: %d\n", retval);
    }

    return 0;
}