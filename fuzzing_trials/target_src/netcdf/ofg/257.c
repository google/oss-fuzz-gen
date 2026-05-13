#include <stdint.h>
#include <stdlib.h>

// Assuming the nc_finalize function is declared in a header file
// If it's not, you may need to include the appropriate header file
// or declare the function prototype here.
int nc_finalize();

int LLVMFuzzerTestOneInput_257(const uint8_t *data, size_t size) {
    // Since nc_finalize does not take any parameters, we don't need to use 'data' or 'size'
    // We simply call the function to test it.
    int result = nc_finalize();

    // Return 0 to indicate the fuzzer should continue
    return 0;
}