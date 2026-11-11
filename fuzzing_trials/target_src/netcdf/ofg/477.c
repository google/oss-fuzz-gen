#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Dummy implementation of nc_inq_var_quantize_477 for demonstration purposes
int nc_inq_var_quantize_477(int param1, int param2, int *param3, int *param4) {
    // Simulate some processing
    if (param1 > 100 && param2 < 50) {
        *param3 = param1 + param2;
        *param4 = param1 - param2;
        return 1;
    }
    return 0;
}

int LLVMFuzzerTestOneInput_477(const uint8_t *data, size_t size) {
    if (size < 16) {
        return 0; // Ensure there's enough data for two integers and two pointers
    }

    // Extract integers from the data
    int param1 = 0;
    int param2 = 0;
    memcpy(&param1, data, sizeof(int));
    memcpy(&param2, data + sizeof(int), sizeof(int));

    // Initialize integer pointers
    int param3_value = 0;
    int param4_value = 0;
    int *param3 = &param3_value;
    int *param4 = &param4_value;

    // Call the function-under-test
    nc_inq_var_quantize_477(param1, param2, param3, param4);

    return 0;
}