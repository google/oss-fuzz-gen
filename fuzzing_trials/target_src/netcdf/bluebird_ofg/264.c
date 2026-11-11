#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

// Assuming the function is defined in some external library
extern int nc_get_vara_uchar(int ncid, int varid, const size_t *start, const size_t *count, unsigned char *data);

int LLVMFuzzerTestOneInput_264(const uint8_t *data, size_t size) {
    if (size < 4 * sizeof(size_t) + 2 * sizeof(int)) {
        // Ensure there is enough data to read the required parameters
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *((int *)data);
    int varid = *((int *)(data + sizeof(int)));

    const size_t *start = (const size_t *)(data + 2 * sizeof(int));
    const size_t *count = (const size_t *)(data + 2 * sizeof(int) + sizeof(size_t) * 2);

    // Calculate the number of elements in the data array
    size_t total_elements = 1;
    for (size_t i = 0; i < 2; i++) {
        total_elements *= count[i];
    }

    // Ensure we have enough data for the unsigned char array
    if (size < 2 * sizeof(int) + 4 * sizeof(size_t) + total_elements) {
        return 0;
    }

    unsigned char *uchar_data = (unsigned char *)(data + 2 * sizeof(int) + 4 * sizeof(size_t));

    // Call the function-under-test
    nc_get_vara_uchar(ncid, varid, start, count, uchar_data);

    return 0;
}