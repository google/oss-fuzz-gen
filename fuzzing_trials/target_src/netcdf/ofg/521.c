#include <stdint.h>
#include <stddef.h>

// Assuming the function is declared in a header file
// #include "netcdf.h"

int nc_get_var_long(int, int, long *);

int LLVMFuzzerTestOneInput_521(const uint8_t *data, size_t size) {
    // Ensure the size is large enough to extract two integers and a long
    if (size < sizeof(int) * 2 + sizeof(long)) {
        return 0;
    }

    // Extract two integers from the data
    int var1 = *(const int *)(data);
    int var2 = *(const int *)(data + sizeof(int));

    // Extract a long from the data
    long var3 = *(const long *)(data + sizeof(int) * 2);

    // Call the function-under-test
    nc_get_var_long(var1, var2, &var3);

    return 0;
}