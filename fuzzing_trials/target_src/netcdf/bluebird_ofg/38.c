#include <stdint.h>
#include <stddef.h>

// Assuming the function nc_set_alignment is defined elsewhere
extern int nc_set_alignment(int, int);

int LLVMFuzzerTestOneInput_38(const uint8_t *data, size_t size) {
    // Ensure we have at least 2 bytes to extract two integers
    if (size < 2) {
        return 0;
    }

    // Extract two integers from the input data
    int param1 = (int)data[0];
    int param2 = (int)data[1];

    // Call the function-under-test with extracted parameters
    nc_set_alignment(param1, param2);

    return 0;
}