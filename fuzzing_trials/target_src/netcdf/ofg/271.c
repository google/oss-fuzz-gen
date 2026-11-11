#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_271(const uint8_t *data, size_t size) {
    // Ensure that the input data is large enough to extract required parameters
    if (size < sizeof(int) * 2 + sizeof(nc_type) + sizeof(size_t) + sizeof(double)) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *(int *)(data);
    int varid = *(int *)(data + sizeof(int));
    const char *name = (const char *)(data + sizeof(int) * 2);
    
    // Ensure the name is null-terminated
    size_t name_len = strnlen(name, size - sizeof(int) * 2);
    if (name_len == size - sizeof(int) * 2) {
        return 0; // Name is not null-terminated within the available size
    }

    nc_type xtype = *(nc_type *)(data + sizeof(int) * 2 + name_len + 1);
    size_t len = *(size_t *)(data + sizeof(int) * 2 + name_len + 1 + sizeof(nc_type));
    
    // Ensure there is enough data for the double array
    if (size < sizeof(int) * 2 + name_len + 1 + sizeof(nc_type) + sizeof(size_t) + len * sizeof(double)) {
        return 0;
    }

    const double *op = (const double *)(data + sizeof(int) * 2 + name_len + 1 + sizeof(nc_type) + sizeof(size_t));

    // Call the function under test
    nc_put_att_double(ncid, varid, name, xtype, len, op);

    return 0;
}