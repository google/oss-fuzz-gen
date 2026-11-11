#include <stdint.h>
#include <stddef.h>

// Assume this is the function-under-test signature
int nc_get_var_ubyte(int arg1, int arg2, unsigned char *arg3);

int LLVMFuzzerTestOneInput_97(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to extract the necessary parameters
    if (size < 3) {
        return 0;
    }

    // Extract parameters from the input data
    int arg1 = (int)data[0];  // Use the first byte for arg1
    int arg2 = (int)data[1];  // Use the second byte for arg2
    unsigned char arg3 = data[2];  // Use the third byte for arg3

    // Call the function-under-test
    nc_get_var_ubyte(arg1, arg2, &arg3);

    return 0;
}