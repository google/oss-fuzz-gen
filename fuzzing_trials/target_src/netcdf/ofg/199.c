#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

// Function signature for the function-under-test
int nc_get_var1_uint(int arg1, int arg2, const size_t *arg3, unsigned int *arg4);

int LLVMFuzzerTestOneInput_199(const uint8_t *data, size_t size) {
    // Ensure there is enough data to initialize the parameters
    if (size < sizeof(size_t) + sizeof(unsigned int)) {
        return 0;
    }

    // Initialize parameters
    int arg1 = (int)data[0]; // Use the first byte as an int
    int arg2 = (int)data[1]; // Use the second byte as an int

    // Use the next bytes to initialize a size_t value
    size_t arg3_value;
    if (size >= sizeof(size_t) + 2) {
        arg3_value = *(const size_t *)(data + 2);
    } else {
        arg3_value = 1; // Default value if not enough data
    }
    const size_t *arg3 = &arg3_value;

    // Use the remaining bytes to initialize an unsigned int value
    unsigned int arg4_value;
    if (size >= sizeof(size_t) + sizeof(unsigned int) + 2) {
        arg4_value = *(const unsigned int *)(data + 2 + sizeof(size_t));
    } else {
        arg4_value = 1; // Default value if not enough data
    }
    unsigned int *arg4 = &arg4_value;

    // Call the function-under-test
    int result = nc_get_var1_uint(arg1, arg2, arg3, arg4);

    return 0;
}