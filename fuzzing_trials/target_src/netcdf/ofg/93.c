#include <stdint.h>
#include <stddef.h>

// Assume the function nc_enddef is defined elsewhere
extern int nc_enddef(int);

int LLVMFuzzerTestOneInput_93(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract an integer
    if (size < sizeof(int)) {
        return 0;
    }

    // Extract an integer from the input data
    int input_value = *(const int*)data;

    // Call the function-under-test
    nc_enddef(input_value);

    return 0;
}