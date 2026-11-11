#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_163(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract meaningful values
    if (size < sizeof(int) + sizeof(nc_type) + 1) {
        return 0;
    }

    // Extract an integer from the data
    int ncid = *(int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    // Extract an nc_type from the data
    nc_type xtype = *(nc_type *)data;
    data += sizeof(nc_type);
    size -= sizeof(nc_type);

    // Allocate memory for the name and ensure it's null-terminated
    char *name = (char *)malloc(size + 1);
    if (name == NULL) {
        return 0;
    }
    memcpy(name, data, size);
    name[size] = '\0';

    // Call the function-under-test
    nc_inq_compound_name(ncid, xtype, name);

    // Free allocated memory
    free(name);

    return 0;
}