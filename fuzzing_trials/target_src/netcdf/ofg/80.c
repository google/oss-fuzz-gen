#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

extern int nc_inq_grp_ncid(int parent_ncid, const char *name, int *grp_ncid);

int LLVMFuzzerTestOneInput_80(const uint8_t *data, size_t size) {
    // Ensure the input data is large enough to be used for the parameters
    if (size < sizeof(int) + 1 + sizeof(int)) {
        return 0;
    }

    // Extract an integer from the data for parent_ncid
    int parent_ncid = *(int *)data;

    // Extract a string from the data for name
    size_t name_len = size - sizeof(int) - sizeof(int);
    char *name = (char *)malloc(name_len + 1);
    if (!name) {
        return 0;
    }
    memcpy(name, data + sizeof(int), name_len);
    name[name_len] = '\0'; // Null-terminate the string

    // Prepare a pointer for grp_ncid
    int grp_ncid = 0;

    // Call the function-under-test
    nc_inq_grp_ncid(parent_ncid, name, &grp_ncid);

    // Clean up
    free(name);

    return 0;
}