#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_231(const uint8_t *data, size_t size) {
    // Initialize variables
    int ncid = 0; // NetCDF file ID
    int varid = 0; // Variable ID
    size_t index = 0; // Index for the variable
    unsigned short value = 0; // Value to be written

    // Ensure the data size is sufficient for our needs
    if (size < sizeof(int) * 2 + sizeof(size_t) + sizeof(unsigned short)) {
        return 0;
    }

    // Extract values from input data
    ncid = *(int *)data;
    varid = *(int *)(data + sizeof(int));
    index = *(size_t *)(data + sizeof(int) * 2);
    value = *(unsigned short *)(data + sizeof(int) * 2 + sizeof(size_t));

    // Call the function-under-test
    nc_put_var1_ushort(ncid, varid, &index, &value);

    return 0;
}