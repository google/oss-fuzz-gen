#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <netcdf.h> // Ensure the NetCDF library is included for nc_put_var_double

// Function-under-test
int nc_put_var_double(int ncid, int varid, const double *op);

int LLVMFuzzerTestOneInput_380(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    int ncid = 1; // Example non-zero value for ncid
    int varid = 1; // Example non-zero value for varid

    // Ensure size is sufficient to hold at least one double
    if (size < sizeof(double)) {
        return 0;
    }

    // Allocate memory for the double array
    double *op = (double *)malloc(size);
    if (op == NULL) {
        return 0;
    }

    // Copy data into the double array
    for (size_t i = 0; i < size / sizeof(double); i++) {
        op[i] = ((double *)data)[i];
    }

    // Call the function-under-test
    nc_put_var_double(ncid, varid, op);

    // Free allocated memory
    free(op);

    return 0;
}