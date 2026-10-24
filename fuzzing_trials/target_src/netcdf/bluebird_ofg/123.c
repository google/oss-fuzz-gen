#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

// Assume the function is defined elsewhere
extern int nc_inq_grpname(int, char *);

int LLVMFuzzerTestOneInput_123(const uint8_t *data, size_t size) {
    // Ensure there's enough data to initialize parameters
    if (size < 4) {
        return 0;
    }

    // Extract an integer from the data
    int grp_id = (int)data[0] | ((int)data[1] << 8) | ((int)data[2] << 16) | ((int)data[3] << 24);

    // Ensure the remaining data is not empty for the name
    size_t name_size = size - 4;
    if (name_size == 0) {
        return 0;
    }

    // Allocate memory for the group name and copy data into it
    char *grp_name = (char *)malloc(name_size + 1);
    if (grp_name == NULL) {
        return 0; // Allocation failed
    }
    memcpy(grp_name, data + 4, name_size);
    grp_name[name_size] = '\0'; // Null-terminate the string

    // Call the function-under-test
    nc_inq_grpname(grp_id, grp_name);

    // Free allocated memory
    free(grp_name);

    return 0;
}