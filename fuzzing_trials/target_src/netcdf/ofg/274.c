#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

// Assume this is the function-under-test
int nc_get_var_int(int param1, int param2, int *param3);

int LLVMFuzzerTestOneInput_274(const uint8_t *data, size_t size) {
    if (size < sizeof(int) * 3) {
        return 0; // Not enough data to extract three integers
    }

    // Extract three integers from the input data
    int param1 = *((int *)(data));
    int param2 = *((int *)(data + sizeof(int)));
    int param3_value = *((int *)(data + 2 * sizeof(int)));
    int *param3 = &param3_value;

    // Call the function-under-test
    int result = nc_get_var_int(param1, param2, param3);

    // Use the result to prevent compiler optimizations from removing the call
    (void)result;

    return 0;
}