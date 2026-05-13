#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

extern int nc_get_att_string(int ncid, int varid, const char *name, char **value);

int LLVMFuzzerTestOneInput_447(const uint8_t *data, size_t size) {
    // Ensure there is enough data for at least the ncid, varid, and a null-terminated string
    if (size < sizeof(int) * 2 + 1) {
        return 0;
    }

    // Extract ncid and varid from the data
    int ncid = *(int *)data;
    int varid = *(int *)(data + sizeof(int));

    // Ensure the rest of the data is null-terminated for the name string
    size_t name_len = size - sizeof(int) * 2;
    char *name = (char *)malloc(name_len + 1);
    if (name == NULL) {
        return 0;
    }
    memcpy(name, data + sizeof(int) * 2, name_len);
    name[name_len] = '\0';

    // Prepare a pointer for the value
    char *value = NULL;

    // Call the function-under-test
    int result = nc_get_att_string(ncid, varid, name, &value);

    // Clean up
    free(name);
    if (value != NULL) {
        free(value);
    }

    return 0;
}