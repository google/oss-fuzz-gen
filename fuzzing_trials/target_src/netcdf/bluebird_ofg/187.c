#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "netcdf.h"

// Function signature for the fuzzer entry point
int LLVMFuzzerTestOneInput_187(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for the parameters
    if (size < sizeof(int) * 2 + 1) {
        return 0;
    }

    // Extract the first two integers from the input data
    int ncid = *(const int *)data;
    int dimid = *(const int *)(data + sizeof(int));

    // Allocate memory for the name buffer
    char name[NC_MAX_NAME + 1]; // NC_MAX_NAME is a typical max length for NetCDF names

    // Call the function-under-test
    nc_inq_dimname(ncid, dimid, name);

    return 0;
}