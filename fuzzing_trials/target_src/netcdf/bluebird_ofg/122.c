#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Function-under-test declaration
int nc_rename_grp(int group_id, const char *new_name);

int LLVMFuzzerTestOneInput_122(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient to create a valid string
    if (size < 2) {
        return 0;
    }

    // Use the first byte of data as the group_id
    int group_id = (int)data[0];

    // Use the remaining bytes as the new name for the group
    char *new_name = (char *)malloc(size);
    if (new_name == NULL) {
        return 0;
    }

    // Copy data to new_name and ensure it is null-terminated
    memcpy(new_name, data + 1, size - 1);
    new_name[size - 1] = '\0';

    // Call the function-under-test
    nc_rename_grp(group_id, new_name);

    // Clean up
    free(new_name);

    return 0;
}