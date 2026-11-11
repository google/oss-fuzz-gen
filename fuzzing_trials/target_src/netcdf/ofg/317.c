#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_317(const uint8_t *data, size_t size) {
    // Ensure the size is large enough to extract the necessary parameters
    if (size < sizeof(int) * 2 + sizeof(short)) {
        return 0;
    }

    // Extract parameters from the data
    int ncid = *(const int *)data;
    int varid = *(const int *)(data + sizeof(int));
    const short *short_data = (const short *)(data + sizeof(int) * 2);

    // Call the function-under-test
    nc_put_var_short(ncid, varid, short_data);

    return 0;
}