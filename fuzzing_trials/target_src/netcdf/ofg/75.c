#include <stdint.h>
#include <stddef.h>

// Function-under-test declaration
int nc_set_alignment(int param1, int param2);

int LLVMFuzzerTestOneInput_75(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract two integers
    if (size < 2 * sizeof(int)) {
        return 0;
    }

    // Extract two integers from the input data
    int param1 = ((int*)data)[0];
    int param2 = ((int*)data)[1];

    // Call the function-under-test with the extracted parameters
    nc_set_alignment(param1, param2);

    return 0;
}