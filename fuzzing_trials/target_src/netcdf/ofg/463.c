#include <stdint.h>
#include <stddef.h>

// Assume this is the function-under-test
int nc_get_var_float(int param1, int param2, float *param3);

int LLVMFuzzerTestOneInput_463(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract parameters
    if (size < sizeof(int) * 2 + sizeof(float)) {
        return 0;
    }

    // Extract parameters from the input data
    int param1 = *(int *)data;
    int param2 = *(int *)(data + sizeof(int));
    float param3_value = *(float *)(data + sizeof(int) * 2);

    // Initialize the float pointer
    float param3 = param3_value;

    // Call the function-under-test
    nc_get_var_float(param1, param2, &param3);

    return 0;
}