#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

// Assume the function is declared in an external library
extern int nc_get_var1_double(int, int, const size_t *, double *);

int LLVMFuzzerTestOneInput_282(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract parameters
    if (size < sizeof(int) * 2 + sizeof(size_t) + sizeof(double)) {
        return 0;
    }

    // Extract parameters from the data
    int param1 = *((int *)data);
    int param2 = *((int *)(data + sizeof(int)));
    const size_t *param3 = (const size_t *)(data + sizeof(int) * 2);
    double *param4 = (double *)(data + sizeof(int) * 2 + sizeof(size_t));

    // Call the function-under-test
    nc_get_var1_double(param1, param2, param3, param4);

    return 0;
}