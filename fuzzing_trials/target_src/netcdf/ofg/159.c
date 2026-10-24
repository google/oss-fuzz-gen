#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

// Assume the function is declared in some header file
int nc_get_var_uchar(int varid, int ncid, unsigned char *value);

int LLVMFuzzerTestOneInput_159(const uint8_t *data, size_t size) {
    // Ensure we have enough data to extract at least two integers
    if (size < 2 * sizeof(int) + sizeof(unsigned char)) {
        return 0;
    }

    // Extract integers from the input data
    int varid = *(const int *)data;
    int ncid = *(const int *)(data + sizeof(int));

    // Allocate memory for the unsigned char value
    unsigned char *value = (unsigned char *)malloc(sizeof(unsigned char));
    if (value == NULL) {
        return 0;
    }

    // Call the function-under-test
    nc_get_var_uchar(varid, ncid, value);

    // Free the allocated memory
    free(value);

    return 0;
}