#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_60(const uint8_t *data, size_t size) {
    // Declare and initialize parameters for nc_put_vara_uchar
    int ncid = 0;  // Assume a valid netCDF file identifier
    int varid = 0; // Assume a valid variable identifier

    // For simplicity, let's assume the dimensions are small and fixed
    size_t start[] = {0, 0}; // Starting index for each dimension
    size_t count[] = {1, 1}; // Number of elements to write in each dimension

    // Ensure the data size is at least the size of the count array
    if (size < sizeof(count)) {
        return 0;
    }

    // Use the provided data as the input for the unsigned char array
    const unsigned char *uchar_data = data;

    // Call the function-under-test
    nc_put_vara_uchar(ncid, varid, start, count, uchar_data);

    return 0;
}