#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

// Assume the function is declared in some included header file
int nc_put_var1_uchar(int ncid, int varid, const size_t *indexp, const unsigned char *op);

int LLVMFuzzerTestOneInput_238(const uint8_t *data, size_t size) {
    // Check if the input size is sufficient to extract parameters
    if (size < sizeof(int) * 2 + sizeof(size_t) + sizeof(unsigned char)) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *(const int *)(data);
    int varid = *(const int *)(data + sizeof(int));
    size_t index = *(const size_t *)(data + sizeof(int) * 2);
    unsigned char value = *(const unsigned char *)(data + sizeof(int) * 2 + sizeof(size_t));

    // Call the function-under-test
    nc_put_var1_uchar(ncid, varid, &index, &value);

    return 0;
}