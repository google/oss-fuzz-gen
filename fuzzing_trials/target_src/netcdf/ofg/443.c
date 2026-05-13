#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

extern int nc_get_att_ushort(int ncid, int varid, const char *name, unsigned short *value);

int LLVMFuzzerTestOneInput_443(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to extract required inputs
    if (size < sizeof(int) * 2 + 1) {
        return 0;
    }

    // Extract ncid and varid from data
    int ncid = *((int *)data);
    int varid = *((int *)(data + sizeof(int)));

    // Extract a null-terminated string for 'name'
    const char *name = (const char *)(data + sizeof(int) * 2);
    size_t name_len = strnlen(name, size - sizeof(int) * 2);

    // Ensure the name is null-terminated within the bounds
    if (name_len >= size - sizeof(int) * 2) {
        return 0;
    }

    // Allocate memory for the unsigned short value
    unsigned short value;
    
    // Call the function-under-test
    int result = nc_get_att_ushort(ncid, varid, name, &value);

    // Use the result and value in some way to avoid compiler optimizations
    printf("Result: %d, Value: %hu\n", result, value);

    return 0;
}