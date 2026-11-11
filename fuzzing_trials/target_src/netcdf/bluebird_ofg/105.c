#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int nc_rename_var(int, int, const char *);

int LLVMFuzzerTestOneInput_105(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0; // Not enough data to proceed
    }

    // Extract integers from the data
    int varid1 = data[0];
    int varid2 = data[1];

    // Ensure there's at least one byte for the string
    size_t str_size = size - 2;
    char *new_name = (char *)malloc(str_size + 1);
    if (new_name == NULL) {
        return 0; // Memory allocation failed
    }

    // Copy the remaining data to the string and null-terminate it
    memcpy(new_name, data + 2, str_size);
    new_name[str_size] = '\0';

    // Call the function-under-test
    nc_rename_var(varid1, varid2, new_name);

    // Free allocated memory
    free(new_name);

    return 0;
}