#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

extern int nc_get_vara_double(int ncid, int varid, const size_t *start, const size_t *count, double *data);

int LLVMFuzzerTestOneInput_54(const uint8_t *data, size_t size) {
    // Ensure we have enough data for ncid, varid, and at least one start and count value
    if (size < sizeof(int) * 2 + sizeof(size_t) * 2) {
        return 0;
    }

    // Extract ncid and varid from the input data
    int ncid = *(const int *)data;
    int varid = *(const int *)(data + sizeof(int));

    // Calculate remaining size for start and count arrays
    size_t remaining_size = size - sizeof(int) * 2;

    // Calculate number of elements for start and count arrays
    size_t num_elements = remaining_size / (sizeof(size_t) * 2);

    // Allocate memory for start and count arrays
    size_t *start = (size_t *)malloc(num_elements * sizeof(size_t));
    size_t *count = (size_t *)malloc(num_elements * sizeof(size_t));

    if (start == NULL || count == NULL) {
        free(start);
        free(count);
        return 0;
    }

    // Fill start and count arrays with data
    for (size_t i = 0; i < num_elements; i++) {
        start[i] = ((const size_t *)(data + sizeof(int) * 2))[i];
        count[i] = ((const size_t *)(data + sizeof(int) * 2 + num_elements * sizeof(size_t)))[i];
    }

    // Allocate memory for the data array
    double *data_array = (double *)malloc(num_elements * sizeof(double));
    if (data_array == NULL) {
        free(start);
        free(count);
        return 0;
    }

    // Call the function-under-test
    nc_get_vara_double(ncid, varid, start, count, data_array);

    // Clean up
    free(start);
    free(count);
    free(data_array);

    return 0;
}