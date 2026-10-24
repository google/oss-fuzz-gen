#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Assuming nc_type is an enum, define it for the purpose of this harness
typedef enum {
    NC_TYPE_INT,
    NC_TYPE_FLOAT,
    NC_TYPE_DOUBLE
} nc_type;

// Mock implementation of nc_copy_data_5 for demonstration purposes
int nc_copy_data_5(int id, nc_type type, const void *src, size_t size, void *dest) {
    if (src == NULL || dest == NULL) {
        return -1; // Error: NULL pointer
    }
    memcpy(dest, src, size);
    return 0; // Success
}

int LLVMFuzzerTestOneInput_5(const uint8_t *data, size_t size) {
    if (size < sizeof(int) + sizeof(nc_type) + 2) {
        return 0; // Not enough data to proceed
    }

    // Extract an integer id from the data
    int id = *(const int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    // Extract an nc_type from the data
    nc_type type = *(const nc_type *)data;
    data += sizeof(nc_type);
    size -= sizeof(nc_type);

    // Ensure there's enough data left for source and destination
    size_t half_size = size / 2;
    const void *src = (const void *)data;
    void *dest = malloc(half_size);
    if (dest == NULL) {
        return 0; // Memory allocation failed
    }

    // Check if src is non-zero to ensure meaningful data is being copied
    if (half_size > 0 && memcmp(src, "\0", half_size) != 0) {
        // Call the function-under-test
        int result = nc_copy_data_5(id, type, src, half_size, dest);
        
        // Optionally, use the result to influence the fuzzing logic
        if (result != 0) {
            fprintf(stderr, "nc_copy_data_5 failed with result: %d\n", result);
        }
    }

    // Clean up
    free(dest);

    return 0;
}