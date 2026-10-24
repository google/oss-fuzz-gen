#include <stdint.h>
#include <stddef.h>

// Assuming the function is declared in a header file
int nc_set_base_pe(int param1, int param2);

int LLVMFuzzerTestOneInput_84(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract two integers
    if (size < 2 * sizeof(int)) {
        return 0;
    }

    // Extract two integers from the input data
    int param1 = *((int*)data);
    int param2 = *((int*)(data + sizeof(int)));

    // Call the function-under-test with the extracted parameters
    nc_set_base_pe(param1, param2);

    return 0;
}