#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_65(const uint8_t *data, size_t size) {
    if (size < sizeof(int) + sizeof(nc_type)) {
        return 0;
    }

    // Extract an integer for the first parameter
    int ncid = *(int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    // Extract an nc_type for the second parameter
    nc_type xtype = *(nc_type *)data;
    data += sizeof(nc_type);
    size -= sizeof(nc_type);

    // Allocate memory for the third parameter (char *)
    char *name = (char *)malloc(size + 1);
    if (name == NULL) {
        return 0;
    }
    memcpy(name, data, size);
    name[size] = '\0'; // Null-terminate the string

    // Allocate memory for the fourth and fifth parameters (size_t *)
    size_t field_count = 0;
    size_t size_per_field = 0;

    // Call the function-under-test
    nc_inq_compound(ncid, xtype, name, &field_count, &size_per_field);

    // Clean up
    free(name);

    return 0;
}