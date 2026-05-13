#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_387(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to extract necessary parameters
    if (size < sizeof(int) * 2 + sizeof(size_t) + sizeof(short)) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *(const int *)data;
    int varid = *(const int *)(data + sizeof(int));
    size_t index = *(const size_t *)(data + sizeof(int) * 2);
    short value = *(const short *)(data + sizeof(int) * 2 + sizeof(size_t));

    // Call the function-under-test
    nc_put_var1_short(ncid, varid, &index, &value);

    return 0;
}