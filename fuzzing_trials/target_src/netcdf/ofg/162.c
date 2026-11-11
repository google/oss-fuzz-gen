#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_162(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract parameters
    if (size < sizeof(int) + sizeof(nc_type) + 1) {
        return 0;
    }

    // Extract the integer parameter
    int ncid = *(int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    // Extract the nc_type parameter
    nc_type xtype = *(nc_type *)data;
    data += sizeof(nc_type);
    size -= sizeof(nc_type);

    // Allocate memory for the char* parameter and copy data into it
    char *name = (char *)malloc(size + 1);
    if (name == NULL) {
        return 0;
    }
    memcpy(name, data, size);
    name[size] = '\0'; // Ensure null-termination

    // Call the function-under-test
    nc_inq_compound_name(ncid, xtype, name);

    // Free allocated memory
    free(name);

    return 0;
}