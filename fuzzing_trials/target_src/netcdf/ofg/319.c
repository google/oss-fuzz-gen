#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_319(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient for meaningful fuzzing
    if (size < 5) {
        return 0;
    }

    // Extract an integer from the data to use as the ncid
    int ncid = (int)data[0];

    // Extract a size_t from the data to use as the length
    size_t length = (size_t)data[1];

    // Extract a string from the data to use as the name
    size_t name_len = size - 3;
    char *name = (char *)malloc(name_len + 1);
    if (name == NULL) {
        return 0;
    }
    memcpy(name, data + 2, name_len);
    name[name_len] = '\0';

    // Prepare a variable to receive the dimension ID
    int dimid;

    // Call the function-under-test
    nc_def_dim(ncid, name, length, &dimid);

    // Clean up
    free(name);

    return 0;
}