#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_365(const uint8_t *data, size_t size) {
    if (size < sizeof(int) * 2 + sizeof(int)) {
        return 0; // Not enough data to fill the parameters
    }

    int ncid = *((int *)data); // Extract the first int for ncid
    int varid = *((int *)(data + sizeof(int))); // Extract the second int for varid

    // Allocate memory for no_fill and fill_value
    int no_fill;
    void *fill_value = malloc(size - sizeof(int) * 2);

    if (fill_value == NULL) {
        return 0; // Memory allocation failed
    }

    // Copy the remaining data into fill_value
    memcpy(fill_value, data + sizeof(int) * 2, size - sizeof(int) * 2);

    // Call the function-under-test
    nc_inq_var_fill(ncid, varid, &no_fill, fill_value);

    // Free the allocated memory
    free(fill_value);

    return 0;
}