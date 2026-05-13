#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_2(const uint8_t *data, size_t size) {
    // Ensure we have enough data to extract parameters
    if (size < sizeof(size_t) * 4 + sizeof(ptrdiff_t) * 2 + sizeof(unsigned char)) {
        return 0;
    }

    // Initialize parameters for nc_get_varm_ubyte
    int ncid = (int)data[0]; // Extracting an int from data
    int varid = (int)data[1]; // Extracting another int from data

    size_t start[1];
    size_t count[1];
    ptrdiff_t stride[1];
    ptrdiff_t imap[1];
    unsigned char value[1];

    // Extracting size_t values from data
    start[0] = (size_t)data[2];
    count[0] = (size_t)data[3];

    // Extracting ptrdiff_t values from data
    stride[0] = (ptrdiff_t)data[4];
    imap[0] = (ptrdiff_t)data[5];

    // Extracting an unsigned char value from data
    value[0] = (unsigned char)data[6];

    // Call the function-under-test
    int result = nc_get_varm_ubyte(ncid, varid, start, count, stride, imap, value);

    // Output the result for debugging purposes (optional)
    printf("Result: %d\n", result);

    return 0;
}