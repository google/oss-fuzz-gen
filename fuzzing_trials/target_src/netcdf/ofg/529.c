#include <stdint.h>
#include <stddef.h>

// Function-under-test declaration
int nc_get_var_longlong(int param1, int param2, long long *output);

int LLVMFuzzerTestOneInput_529(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to extract two integers
    if (size < sizeof(int) * 2) {
        return 0;
    }

    // Extract two integers from the input data
    int param1 = *(int *)(data);
    int param2 = *(int *)(data + sizeof(int));

    // Initialize a long long variable to pass to the function
    long long output = 0;

    // Call the function-under-test
    nc_get_var_longlong(param1, param2, &output);

    return 0;
}