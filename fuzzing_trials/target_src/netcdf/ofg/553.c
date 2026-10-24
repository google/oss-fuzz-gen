#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>  // Include for memset

extern int nc_get_vars_ubyte(int ncid, int varid, const size_t *start, const size_t *count, const ptrdiff_t *stride, unsigned char *data);

int LLVMFuzzerTestOneInput_553(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our needs
    if (size < 5 * sizeof(size_t) + sizeof(ptrdiff_t) + sizeof(unsigned char)) {
        return 0;
    }

    // Initialize parameters for nc_get_vars_ubyte
    int ncid = data[0];
    int varid = data[1];

    // Use the rest of the data to fill the size_t arrays and ptrdiff_t
    const size_t *start = (const size_t *)(data + 2);
    const size_t *count = (const size_t *)(data + 2 + sizeof(size_t));
    const ptrdiff_t *stride = (const ptrdiff_t *)(data + 2 + 2 * sizeof(size_t));

    // Calculate the length of data to be retrieved based on count
    size_t data_length = *count * sizeof(unsigned char);
    if (data_length > size - (2 + 2 * sizeof(size_t) + sizeof(ptrdiff_t))) {
        return 0;  // Avoid out-of-bounds access
    }

    // Allocate memory for output_data
    unsigned char *output_data = (unsigned char *)malloc(data_length);
    if (!output_data) {
        return 0;  // Allocation failed
    }

    // Initialize output_data to zero
    memset(output_data, 0, data_length);

    // Call the function-under-test
    nc_get_vars_ubyte(ncid, varid, start, count, stride, output_data);

    // Free the allocated memory
    free(output_data);

    return 0;
}