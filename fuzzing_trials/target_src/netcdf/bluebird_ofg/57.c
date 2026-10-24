#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_57(const uint8_t *data, size_t size) {
    // Ensure there is enough data for the parameters
    if (size < sizeof(int) * 2 + sizeof(nc_type) + sizeof(size_t) + 1) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *(int *)data;
    int varid = *(int *)(data + sizeof(int));

    // Ensure that there is a null-terminated string for 'name'
    size_t name_len = strnlen((const char *)(data + sizeof(int) * 2), size - sizeof(int) * 2);
    if (name_len == size - sizeof(int) * 2 || name_len == 0) {
        return 0;
    }
    const char *name = (const char *)(data + sizeof(int) * 2);

    // Calculate offset after 'name'
    size_t offset_after_name = sizeof(int) * 2 + name_len + 1;
    if (offset_after_name + sizeof(nc_type) + sizeof(size_t) > size) {
        return 0;
    }

    nc_type xtype = *(nc_type *)(data + offset_after_name);
    size_t len = *(size_t *)(data + offset_after_name + sizeof(nc_type));

    // Ensure len is not too large to avoid excessive memory allocation
    if (len > 1000) {
        len = 1000;
    }

    // Allocate memory for the double array
    double *values = (double *)malloc(len * sizeof(double));
    if (values == NULL) {
        return 0;
    }

    // Fill the double array with values from the input data
    size_t offset = offset_after_name + sizeof(nc_type) + sizeof(size_t);
    for (size_t i = 0; i < len && offset + sizeof(double) <= size; i++) {
        values[i] = *(double *)(data + offset);
        offset += sizeof(double);
    }

    // Call the function-under-test
    nc_put_att_double(ncid, varid, name, xtype, len, values);

    // Free allocated memory
    free(values);

    return 0;
}