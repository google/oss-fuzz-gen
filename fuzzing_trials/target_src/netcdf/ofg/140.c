#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

// Assuming the function is declared somewhere else
extern int nc_get_alignment(int *, int *);

int LLVMFuzzerTestOneInput_140(const uint8_t *data, size_t size) {
    // Declare and initialize the variables
    int alignment1 = 0;
    int alignment2 = 0;

    // Ensure we have enough data to extract two integers
    if (size < 2 * sizeof(int)) {
        return 0;
    }

    // Copy data into the integers
    alignment1 = *((int *)data);
    alignment2 = *((int *)(data + sizeof(int)));

    // Call the function-under-test
    nc_get_alignment(&alignment1, &alignment2);

    return 0;
}