#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

// Mock function signature for nc_get_var_float
int nc_get_var_float(int arg1, int arg2, float *arg3);

// Fuzzing harness
int LLVMFuzzerTestOneInput_464(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to extract two integers and a float
    if (size < sizeof(int) * 2 + sizeof(float)) {
        return 0;
    }

    // Extract the first integer
    int arg1 = *((int *)data);
    data += sizeof(int);
    size -= sizeof(int);

    // Extract the second integer
    int arg2 = *((int *)data);
    data += sizeof(int);
    size -= sizeof(int);

    // Extract the float
    float arg3 = *((float *)data);

    // Call the function-under-test
    nc_get_var_float(arg1, arg2, &arg3);

    return 0;
}