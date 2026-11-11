#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_275(const uint8_t *data, size_t size) {
    // Ensure we have enough data for the parameters
    if (size < sizeof(size_t) * 4 + sizeof(unsigned short)) {
        return 0;
    }

    // Extract parameters from the data
    int ncid = (int)data[0];
    int varid = (int)data[1];

    const size_t *start = (const size_t *)(data + 2);
    const size_t *count = (const size_t *)(data + 2 + sizeof(size_t) * 2);

    const unsigned short *ushort_data = (const unsigned short *)(data + 2 + sizeof(size_t) * 4);

    // Call the function-under-test
    nc_put_vara_ushort(ncid, varid, start, count, ushort_data);

    return 0;
}