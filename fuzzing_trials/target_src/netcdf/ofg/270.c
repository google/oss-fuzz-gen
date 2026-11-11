#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_270(const uint8_t *data, size_t size) {
    // Ensure there's enough data for the inputs
    if (size < 8) {
        return 0;
    }

    // Extract an integer from the data for the first parameter
    int ncid = *(int *)data;

    // Use part of the data as a string for the second parameter
    size_t str_len = size - 8;
    char *name = (char *)malloc(str_len + 1);
    if (name == NULL) {
        return 0;
    }
    memcpy(name, data + 8, str_len);
    name[str_len] = '\0'; // Null-terminate the string

    // Prepare an integer for the third parameter
    int new_ncid = 0;

    // Call the function-under-test
    int result = nc_def_grp(ncid, name, &new_ncid);

    // Free allocated memory
    free(name);

    // Return 0 as required by the fuzzer
    return 0;
}