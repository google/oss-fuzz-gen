#include <stdint.h>
#include <stddef.h>

// Assume that the function nc_def_var_szip is declared in some header file
// and is linked during the compilation.
extern int nc_def_var_szip(int, int, int, int);

int LLVMFuzzerTestOneInput_88(const uint8_t *data, size_t size) {
    if (size < sizeof(int) * 4) {
        // Ensure there is enough data to fill all four integer parameters
        return 0;
    }

    // Extract four integers from the input data
    int param1 = *((int *)data);
    int param2 = *((int *)(data + sizeof(int)));
    int param3 = *((int *)(data + 2 * sizeof(int)));
    int param4 = *((int *)(data + 3 * sizeof(int)));

    // Call the function-under-test with the extracted parameters
    nc_def_var_szip(param1, param2, param3, param4);

    return 0;
}