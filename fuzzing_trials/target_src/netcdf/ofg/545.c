#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_545(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for our needs
    if (size < 10) {
        return 0;
    }

    // Extract integers from the data
    int ncid = *(const int *)data;
    int varid = *(const int *)(data + 4);

    // Use the rest of the data as a string for the attribute name
    size_t name_length = size - 8;
    char *name = (char *)malloc(name_length + 1);
    if (name == NULL) {
        return 0;
    }
    memcpy(name, data + 8, name_length);
    name[name_length] = '\0';

    // Prepare an integer pointer for the attribute ID
    int attid;
    
    // Call the function under test
    nc_inq_attid(ncid, varid, name, &attid);

    // Clean up
    free(name);

    return 0;
}