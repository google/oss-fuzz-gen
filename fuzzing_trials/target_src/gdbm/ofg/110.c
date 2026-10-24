#include <stdint.h>
#include <stddef.h>  // Include this to define size_t

// Function-under-test
void variables_init(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput_110(const uint8_t *data, size_t size) {
    // Call the function-under-test with input data
    variables_init(data, size);

    return 0;
}