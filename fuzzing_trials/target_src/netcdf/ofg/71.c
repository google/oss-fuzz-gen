#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Function-under-test declaration
int nc_rename_grp(int group_id, const char *new_name);

int LLVMFuzzerTestOneInput_71(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for testing
    if (size < 2) {
        return 0;
    }

    // Extract an integer from the input data for the group_id
    int group_id = (int)data[0];

    // Create a null-terminated string for the new_name
    char new_name[256];
    size_t name_size = size - 1;
    if (name_size > sizeof(new_name) - 1) {
        name_size = sizeof(new_name) - 1;
    }
    memcpy(new_name, &data[1], name_size);
    new_name[name_size] = '\0';

    // Call the function-under-test
    nc_rename_grp(group_id, new_name);

    return 0;
}