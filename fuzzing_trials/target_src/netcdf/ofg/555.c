#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_555(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to extract parameters
    if (size < sizeof(int) * 2 + 1) {
        return 0;
    }

    // Extract the first integer parameter
    int param1 = *(const int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    // Extract the second integer parameter
    int param2 = *(const int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    // Use the remaining data as the unsigned char array
    const unsigned char *uchar_array = (const unsigned char *)data;

    // Call the function-under-test
    nc_put_var_ubyte(param1, param2, uchar_array);

    return 0;
}