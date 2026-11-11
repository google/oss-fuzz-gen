#include <stdint.h>
#include <stddef.h>

// Assuming the function is declared in some header file
int nc_get_var_double(int, int, double *);

// Remove the 'extern "C"' as it is not needed in C code
int LLVMFuzzerTestOneInput_104(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    int var1 = 0;
    int var2 = 0;
    double result = 0.0;

    // Ensure that the size is sufficient to extract two integers
    if (size >= 2 * sizeof(int)) {
        // Extract two integers from the input data
        var1 = *((int *)data);
        var2 = *((int *)(data + sizeof(int)));
    }

    // Call the function-under-test
    nc_get_var_double(var1, var2, &result);

    return 0;
}