#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Mock implementation of nc_inq_var_deflate_137 for demonstration purposes
int nc_inq_var_deflate_137(int ncid, int varid, int *shufflep, int *deflatep, int *deflate_levelp) {
    // This is a placeholder function. The real implementation would interact with a netCDF file.
    if (shufflep != NULL) *shufflep = 1;
    if (deflatep != NULL) *deflatep = 1;
    if (deflate_levelp != NULL) *deflate_levelp = 5;
    return 0; // Assume success
}

extern int LLVMFuzzerTestOneInput_137(const uint8_t *data, size_t size) {
    // Ensure we have enough data to extract integers
    if (size < sizeof(int) * 2) {
        return 0;
    }

    // Extract integers from the input data
    int ncid, varid;
    memcpy(&ncid, data, sizeof(int));
    memcpy(&varid, data + sizeof(int), sizeof(int));

    // Declare and initialize pointers for the function call
    int shuffle, deflate, deflate_level;
    int *shufflep = &shuffle;
    int *deflatep = &deflate;
    int *deflate_levelp = &deflate_level;

    // Call the function-under-test
    nc_inq_var_deflate_137(ncid, varid, shufflep, deflatep, deflate_levelp);

    // Utilize the output values to ensure they are being processed
    // This is a simple way to ensure the function output is used, which may help with code coverage
    if (shuffle != 0 && deflate != 0 && deflate_level != 0) {
        return shuffle + deflate + deflate_level;
    }

    return 0;
}