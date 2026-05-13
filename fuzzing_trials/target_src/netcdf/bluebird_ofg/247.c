#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

// Assume that the function nc_get_var_double is defined elsewhere
extern int nc_get_var_double(int, int, double *);

int LLVMFuzzerTestOneInput_247(const uint8_t *data, size_t size) {
    if (size < 2 * sizeof(int) + sizeof(double)) {
        return 0;
    }

    // Extract two integers from the data
    int var1 = *(const int *)data;
    int var2 = *(const int *)(data + sizeof(int));

    // Allocate memory for a double
    double *var3 = (double *)malloc(sizeof(double));
    if (var3 == NULL) {
        return 0;
    }

    // Extract a double from the data
    *var3 = *(const double *)(data + 2 * sizeof(int));

    // Call the function-under-test
    nc_get_var_double(var1, var2, var3);

    // Free the allocated memory
    free(var3);

    return 0;
}