#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_523(const uint8_t *data, size_t size) {
    int ncid;
    size_t type_size;
    char *name;
    nc_type type;

    // Ensure the data is large enough to extract meaningful values
    if (size < sizeof(int) + sizeof(size_t) + 1) {
        return 0;
    }

    // Extract the first integer from the data to use as ncid
    memcpy(&ncid, data, sizeof(int));
    data += sizeof(int);
    size -= sizeof(int);

    // Extract the next size_t from the data to use as type_size
    memcpy(&type_size, data, sizeof(size_t));
    data += sizeof(size_t);
    size -= sizeof(size_t);

    // Allocate memory for the name and copy a portion of the data into it
    name = (char *)malloc(size + 1);
    if (name == NULL) {
        return 0;
    }
    memcpy(name, data, size);
    name[size] = '\0'; // Null-terminate the string

    // Call the function-under-test
    nc_def_compound(ncid, type_size, name, &type);

    // Clean up
    free(name);

    return 0;
}