#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Mock function for demonstration purposes
int nc_get_var_short_7(int param1, int param2, short *param3) {
    // Function implementation here
    // For demonstration, let's assume it modifies the value pointed by param3
    if (param3 != NULL) {
        *param3 = param1 + param2; // Example operation
    }
    return 0; // Return a dummy value
}

int LLVMFuzzerTestOneInput_7(const uint8_t *data, size_t size) {
    if (size < sizeof(int) * 2 + sizeof(short)) {
        return 0; // Not enough data to fill parameters
    }

    // Extract parameters from the input data
    int param1 = *(int *)data;
    int param2 = *(int *)(data + sizeof(int));
    short param3_value = *(short *)(data + sizeof(int) * 2);
    short *param3 = &param3_value;

    // Call the function-under-test with the extracted parameters
    nc_get_var_short_7(param1, param2, param3);

    // Additionally, test the function with a NULL param3 to increase coverage
    nc_get_var_short_7(param1, param2, NULL);

    // Introduce variations in the input to explore different code paths
    if (param1 != param2) {
        nc_get_var_short_7(param2, param1, param3);
    }

    if (param3_value > 0) {
        nc_get_var_short_7(param1, -param2, param3);
    }

    // Additional variations to increase code coverage
    if (param3_value < 0) {
        nc_get_var_short_7(-param1, param2, param3);
    }

    if (param1 == 0 || param2 == 0) {
        nc_get_var_short_7(param1, param2, param3);
    }

    return 0;
}