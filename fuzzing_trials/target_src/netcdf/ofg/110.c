#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

// Assume this is the function-under-test from the NetCDF library
int nc_put_var_uchar(int ncid, int varid, const unsigned char *op);

int LLVMFuzzerTestOneInput_110(const uint8_t *data, size_t size) {
    // Ensure that size is sufficient to extract at least two integers
    if (size < sizeof(int) * 2) {
        return 0;
    }

    // Extract ncid and varid from data
    int ncid = *(const int *)data;
    int varid = *(const int *)(data + sizeof(int));

    // Ensure that the remaining data can be used as the unsigned char array
    const unsigned char *uchar_data = (const unsigned char *)(data + sizeof(int) * 2);
    size_t uchar_data_size = size - sizeof(int) * 2;

    // Call the function-under-test
    nc_put_var_uchar(ncid, varid, uchar_data);

    return 0;
}