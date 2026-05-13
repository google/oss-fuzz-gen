#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Assuming the function is declared in a header file like this
// #include "netcdf.h"

// Mock function for demonstration purposes
int nc_get_att_ushort_442(int ncid, int varid, const char *name, unsigned short *value) {
    // Implementation would be here
    return 0;
}

int LLVMFuzzerTestOneInput_442(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract meaningful values
    if (size < sizeof(int) * 2 + 1 + sizeof(unsigned short)) {
        return 0;
    }

    // Extracting parameters from the input data
    int ncid = *((int *)data);
    int varid = *((int *)(data + sizeof(int)));
    const char *name = (const char *)(data + sizeof(int) * 2);
    unsigned short value;

    // Call the function-under-test
    nc_get_att_ushort_442(ncid, varid, name, &value);

    return 0;
}