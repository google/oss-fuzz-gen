#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

// Assume nc_inq_attname is defined somewhere
int nc_inq_attname(int ncid, int varid, int attnum, char *name);

int LLVMFuzzerTestOneInput_360(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to extract required integer values
    if (size < sizeof(int) * 3 + 1) {
        return 0;
    }

    // Extract integers from the input data
    int ncid = *((int *)data);
    int varid = *((int *)(data + sizeof(int)));
    int attnum = *((int *)(data + 2 * sizeof(int)));

    // Allocate a buffer for the name, ensuring it is non-NULL
    char name[256];
    memset(name, 0, sizeof(name));

    // Call the function-under-test
    nc_inq_attname(ncid, varid, attnum, name);

    return 0;
}