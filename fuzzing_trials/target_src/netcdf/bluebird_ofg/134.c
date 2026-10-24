#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h> // Include for memcpy

extern int nc_put_varm_uint(int ncid, int varid, const size_t *start, const size_t *count, const ptrdiff_t *stride, const ptrdiff_t *imap, const unsigned int *op);

int LLVMFuzzerTestOneInput_134(const uint8_t *data, size_t size) {
    // Define the number of elements for each array
    const size_t num_elements = 2;

    // Calculate the total size needed for all parameters
    size_t total_size_needed = 2 * sizeof(int) + 2 * num_elements * sizeof(size_t) + 2 * num_elements * sizeof(ptrdiff_t) + sizeof(unsigned int);

    // Ensure there's enough data for all parameters
    if (size < total_size_needed) {
        return 0;
    }

    int ncid;
    int varid;
    size_t start[num_elements];
    size_t count[num_elements];
    ptrdiff_t stride[num_elements];
    ptrdiff_t imap[num_elements];
    unsigned int op;

    // Use memcpy to safely copy data into variables
    memcpy(&ncid, data, sizeof(int));
    memcpy(&varid, data + sizeof(int), sizeof(int));
    memcpy(start, data + 2 * sizeof(int), num_elements * sizeof(size_t));
    memcpy(count, data + 2 * sizeof(int) + num_elements * sizeof(size_t), num_elements * sizeof(size_t));
    memcpy(stride, data + 2 * sizeof(int) + 2 * num_elements * sizeof(size_t), num_elements * sizeof(ptrdiff_t));
    memcpy(imap, data + 2 * sizeof(int) + 2 * num_elements * sizeof(size_t) + num_elements * sizeof(ptrdiff_t), num_elements * sizeof(ptrdiff_t));
    memcpy(&op, data + 2 * sizeof(int) + 2 * num_elements * sizeof(size_t) + 2 * num_elements * sizeof(ptrdiff_t), sizeof(unsigned int));

    // Call the function with the extracted parameters
    nc_put_varm_uint(ncid, varid, start, count, stride, imap, &op);

    return 0;
}