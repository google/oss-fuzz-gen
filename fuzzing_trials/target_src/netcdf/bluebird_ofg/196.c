#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_196(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to extract two integers and at least one double
    if (size < sizeof(int) * 2 + sizeof(double)) {
        return 0;
    }

    // Extract the first integer
    int ncid = *((int*)data);
    data += sizeof(int);
    size -= sizeof(int);

    // Extract the second integer
    int varid = *((int*)data);
    data += sizeof(int);
    size -= sizeof(int);

    // Allocate memory for the double array
    size_t num_doubles = size / sizeof(double);
    if (num_doubles == 0) {
        return 0;
    }

    double *values = (double*)malloc(num_doubles * sizeof(double));
    if (values == NULL) {
        return 0;
    }

    // Copy the remaining bytes into the double array
    for (size_t i = 0; i < num_doubles; i++) {
        values[i] = ((double*)data)[i];
    }

    // Call the function-under-test
    nc_put_var_double(ncid, varid, values);

    // Free the allocated memory
    free(values);

    return 0;
}