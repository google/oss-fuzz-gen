#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_276(const uint8_t *data, size_t size) {
    // Ensure there's enough data to extract parameters
    if (size < sizeof(size_t) * 2 + sizeof(unsigned short)) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = (int)data[0]; // Assuming ncid is a byte-sized value for simplicity
    int varid = (int)data[1]; // Assuming varid is a byte-sized value for simplicity
    const size_t *start = (const size_t *)(data + 2);
    const size_t *count = (const size_t *)(data + 2 + sizeof(size_t));
    const unsigned short *value = (const unsigned short *)(data + 2 + sizeof(size_t) * 2);

    // Call the function-under-test
    int result = nc_put_vara_ushort(ncid, varid, start, count, value);

    // Print the result for debugging purposes
    printf("nc_put_vara_ushort returned: %d\n", result);

    return 0;
}