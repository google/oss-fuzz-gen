#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_269(const uint8_t *data, size_t size) {
    // Ensure the data is large enough to extract required parameters
    if (size < 5) {
        return 0;
    }

    // Extract an integer from the data for the ncid parameter
    int ncid = (int)data[0];

    // Extract a string for the name parameter
    // Ensure the string is null-terminated and non-empty
    size_t name_len = size - 2;
    char *name = (char *)malloc(name_len + 1);
    if (name == NULL) {
        return 0;
    }
    memcpy(name, &data[1], name_len);
    name[name_len] = '\0';

    // Prepare the new_ncid parameter
    int new_ncid;

    // Call the function-under-test
    int result = nc_def_grp(ncid, name, &new_ncid);

    // Free allocated memory
    free(name);

    return 0;
}