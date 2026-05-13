#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_504(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient for our needs
    if (size < sizeof(size_t) + sizeof(int)) {
        return 0;
    }

    // Extract values from the input data
    int ncid = *(const int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    int varid = *(const int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    // Use the remaining data to create a size_t index and an int value
    size_t index = *(const size_t *)data;
    data += sizeof(size_t);
    size -= sizeof(size_t);

    int value = *(const int *)data;

    // Call the function-under-test
    nc_put_var1_int(ncid, varid, &index, &value);

    return 0;
}