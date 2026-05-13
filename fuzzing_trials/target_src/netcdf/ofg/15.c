#include <stdint.h>
#include <stddef.h>

// Assuming the function nc_sync is defined somewhere
int nc_sync(int value);

int LLVMFuzzerTestOneInput_15(const uint8_t *data, size_t size) {
    // Ensure that there is enough data to extract an integer
    if (size < sizeof(int)) {
        return 0;
    }

    // Extract an integer from the input data
    int value = *(const int*)data;

    // Call the function-under-test
    nc_sync(value);

    return 0;
}