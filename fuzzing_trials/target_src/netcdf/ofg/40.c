#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_40(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient to extract necessary parameters
    if (size < sizeof(int) * 2 + sizeof(size_t) * 2) {
        return 0;
    }

    // Extract parameters from the input data
    const int ncid = *(const int *)(data);
    const int varid = *(const int *)(data + sizeof(int));
    const size_t *start = (const size_t *)(data + sizeof(int) * 2);
    const size_t *count = (const size_t *)(data + sizeof(int) * 2 + sizeof(size_t));

    // Ensure that the remaining data is sufficient for the int array
    size_t remaining_size = size - (sizeof(int) * 2 + sizeof(size_t) * 2);
    size_t int_array_size = remaining_size / sizeof(int);
    const int *values = (const int *)(data + sizeof(int) * 2 + sizeof(size_t) * 2);

    // Call the function-under-test
    nc_put_vara_int(ncid, varid, start, count, values);

    return 0;
}