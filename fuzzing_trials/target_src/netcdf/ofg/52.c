#include <stdint.h>
#include <stddef.h>

// Declaration of the function-under-test
int nc_redef(int);

int LLVMFuzzerTestOneInput_52(const uint8_t *data, size_t size) {
    // Ensure there is enough data to read an integer
    if (size < sizeof(int)) {
        return 0;
    }

    // Extract an integer from the input data
    int input_value = *(const int *)data;

    // Call the function-under-test with the extracted integer
    nc_redef(input_value);

    return 0;
}