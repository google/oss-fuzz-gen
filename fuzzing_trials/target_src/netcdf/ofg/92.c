#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Assume the function is declared in a header file
int nc_inq_grpname(int grp_id, char *name);

int LLVMFuzzerTestOneInput_92(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient for the test
    if (size < sizeof(int) + 1) {
        return 0;
    }

    // Extract an integer from the data
    int grp_id = *(int *)data;

    // Allocate memory for the name buffer
    size_t name_size = size - sizeof(int);
    char *name = (char *)malloc(name_size + 1);
    if (name == NULL) {
        return 0;
    }

    // Copy the remaining data into the name buffer and null-terminate it
    memcpy(name, data + sizeof(int), name_size);
    name[name_size] = '\0';

    // Call the function-under-test
    nc_inq_grpname(grp_id, name);

    // Free the allocated memory
    free(name);

    return 0;
}