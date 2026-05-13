#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>  // Make sure to include the netCDF library

int LLVMFuzzerTestOneInput_23(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient for meaningful input
    if (size < 4) {
        return 0;
    }

    // Extract an integer from the data for the first parameter (ncid)
    int ncid = *(int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    // Use the remaining data as a string for the second parameter (name)
    char *name = (char *)malloc(size + 1);
    if (name == NULL) {
        return 0;
    }
    memcpy(name, data, size);
    name[size] = '\0';  // Ensure null-termination

    // Prepare a pointer for the third parameter (dimidp)
    int dimid;
    int *dimidp = &dimid;

    // Call the function-under-test
    nc_inq_dimid(ncid, name, dimidp);

    // Clean up
    free(name);

    return 0;
}