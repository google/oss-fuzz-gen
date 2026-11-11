#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_533(const uint8_t *data, size_t size) {
    int ncid = 0; // Sample netCDF file ID
    int varid = 0; // Sample variable ID
    unsigned short *ushort_data;

    // Ensure there is enough data to read at least one unsigned short
    if (size < sizeof(unsigned short)) {
        return 0;
    }

    // Allocate memory for ushort_data and copy data into it
    ushort_data = (unsigned short *)malloc(size);
    if (ushort_data == NULL) {
        return 0;
    }

    // Copy the input data into ushort_data
    for (size_t i = 0; i < size / sizeof(unsigned short); i++) {
        ushort_data[i] = ((unsigned short *)data)[i];
    }

    // Call the function-under-test
    nc_put_var_ushort(ncid, varid, ushort_data);

    // Free allocated memory
    free(ushort_data);

    return 0;
}