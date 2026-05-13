#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Assuming the function is part of a library that needs to be included
#include <netcdf.h>

int LLVMFuzzerTestOneInput_462(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to create a meaningful input
    if (size < 2) {
        return 0;
    }

    // Extract an integer from the data for the first parameter
    int ncid = (int)data[0];

    // Allocate memory for the string parameter and ensure it is null-terminated
    size_t str_len = size - 1;  // Leave space for the null terminator
    char *name = (char *)malloc(str_len + 1);
    if (name == NULL) {
        return 0;
    }
    memcpy(name, data + 1, str_len);
    name[str_len] = '\0';

    // Prepare the third parameter
    int grp_ncid;

    // Call the function-under-test
    int result = nc_inq_grp_full_ncid(ncid, name, &grp_ncid);

    // Clean up
    free(name);

    return 0;
}