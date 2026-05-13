#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int nc_rename_var(int, int, const char *);

int LLVMFuzzerTestOneInput_543(const uint8_t *data, size_t size) {
    if (size < 3) {
        // Ensure there's enough data for two integers and a string
        return 0;
    }

    // Extract two integers from the data
    int varid1 = (int)data[0];
    int varid2 = (int)data[1];

    // Create a null-terminated string from the remaining data
    size_t str_size = size - 2;
    char *newname = (char *)malloc(str_size + 1);
    if (newname == NULL) {
        return 0;
    }
    memcpy(newname, data + 2, str_size);
    newname[str_size] = '\0';

    // Call the function under test
    nc_rename_var(varid1, varid2, newname);

    // Free the allocated memory
    free(newname);

    return 0;
}