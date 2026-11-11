#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

extern int nc_get_att_longlong(int ncid, int varid, const char *name, long long *value);

int LLVMFuzzerTestOneInput_83(const uint8_t *data, size_t size) {
    if (size < 4) {
        return 0;
    }

    int ncid = (int)data[0];
    int varid = (int)data[1];

    // Ensure there is at least one byte for the name and one for the value
    size_t name_length = size - 3;
    char *name = (char *)malloc(name_length + 1);
    if (name == NULL) {
        return 0;
    }
    memcpy(name, data + 2, name_length);
    name[name_length] = '\0';  // Null-terminate the string

    long long value;
    int result = nc_get_att_longlong(ncid, varid, name, &value);

    free(name);
    return 0;
}