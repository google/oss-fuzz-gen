#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Assuming the function is declared somewhere
int nc_get_vara_int(int ncid, int varid, const size_t *start, const size_t *count, int *data);

int LLVMFuzzerTestOneInput_263(const uint8_t *data, size_t size) {
    if (size < 4) {
        return 0; // Not enough data to proceed
    }

    // Extract ncid and varid from the input data
    int ncid = data[0];
    int varid = data[1];

    // Define start and count arrays
    size_t start[2] = {0, 0};
    size_t count[2] = {1, 1};

    // Use input data to set start and count if possible
    if (size >= 8) {
        memcpy(start, data + 2, sizeof(size_t));
        memcpy(count, data + 2 + sizeof(size_t), sizeof(size_t));
    }

    // Allocate memory for the data array
    int data_array[2] = {0, 0};

    // Call the function-under-test
    nc_get_vara_int(ncid, varid, start, count, data_array);

    return 0;
}