#include <stdint.h>
#include <stddef.h>

// Mock function definition for nc_def_var_szip
// In actual implementation, this would be included from the appropriate header file.
int nc_def_var_szip(int param1, int param2, int param3, int param4);

int LLVMFuzzerTestOneInput_87(const uint8_t *data, size_t size) {
    // Ensure we have enough data to extract four integers
    if (size < sizeof(int) * 4) {
        return 0;
    }

    // Extract four integers from the input data
    int param1 = *(const int *)(data);
    int param2 = *(const int *)(data + sizeof(int));
    int param3 = *(const int *)(data + 2 * sizeof(int));
    int param4 = *(const int *)(data + 3 * sizeof(int));

    // Call the function-under-test
    nc_def_var_szip(param1, param2, param3, param4);

    return 0;
}