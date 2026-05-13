#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Assuming the function is part of a library that we need to include
#include <netcdf.h>

int LLVMFuzzerTestOneInput_79(const uint8_t *data, size_t size) {
    if (size < 5) {
        // Ensure there's enough data for the parameters
        return 0;
    }

    // Extract an integer from the data
    int ncid = (int)data[0];

    // Use a portion of the data as a string, ensuring null-termination
    size_t string_len = size - 4;
    char *name = (char *)malloc(string_len + 1);
    if (name == NULL) {
        return 0;
    }
    memcpy(name, data + 1, string_len);
    name[string_len] = '\0';

    // Prepare a pointer to an integer for the result
    int grpid;
    int *grp_id_ptr = &grpid;

    // Call the function-under-test
    nc_inq_grp_ncid(ncid, name, grp_id_ptr);

    // Clean up
    free(name);

    return 0;
}