#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

extern int nc_get_var1_uint(int ncid, int varid, const size_t *indexp, unsigned int *ip);

int LLVMFuzzerTestOneInput_198(const uint8_t *data, size_t size) {
    if (size < sizeof(size_t) + sizeof(unsigned int)) {
        return 0;
    }

    int ncid = (int)data[0];
    int varid = (int)data[1];

    // Ensure there's enough data for the index and output variable
    size_t index = 0;
    unsigned int output = 0;

    if (size >= sizeof(size_t) + sizeof(unsigned int)) {
        index = *(const size_t *)(data + 2);
        output = *(const unsigned int *)(data + 2 + sizeof(size_t));
    }

    // Call the function-under-test
    nc_get_var1_uint(ncid, varid, &index, &output);

    return 0;
}