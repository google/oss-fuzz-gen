#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

// Assuming the function is declared in some header file, include it here
// #include "netcdf.h" // or the appropriate header file where nc_inq is declared

// Mock implementation of nc_inq for demonstration purposes
// Remove this when using the actual function from the library
// int nc_inq(int ncid, int *ndims, int *nvars, int *natts, int *unlimdimid) {
//     // Simulate some processing
//     if (ncid < 0) return -1; // Error for invalid ncid
//     if (ndims) *ndims = 10;
//     if (nvars) *nvars = 20;
//     if (natts) *natts = 5;
//     if (unlimdimid) *unlimdimid = 0;
//     return 0; // Success
// }

int LLVMFuzzerTestOneInput_482(const uint8_t *data, size_t size) {
    if (size < sizeof(int)) {
        return 0; // Not enough data to extract an integer
    }

    int ncid = *((int *)data);

    int ndims = 0;
    int nvars = 0;
    int natts = 0;
    int unlimdimid = 0;

    // Call the function-under-test
    nc_inq(ncid, &ndims, &nvars, &natts, &unlimdimid);

    return 0;
}