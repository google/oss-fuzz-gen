#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "netcdf.h"

// Function to convert raw data to a valid size_t value
size_t extract_size_t(const uint8_t *data) {
    size_t value = 0;
    for (size_t i = 0; i < sizeof(size_t); i++) {
        value |= ((size_t)data[i]) << (i * 8);
    }
    return value;
}

// Function to convert raw data to a valid ptrdiff_t value
ptrdiff_t extract_ptrdiff_t(const uint8_t *data) {
    ptrdiff_t value = 0;
    for (size_t i = 0; i < sizeof(ptrdiff_t); i++) {
        value |= ((ptrdiff_t)data[i]) << (i * 8);
    }
    return value;
}

int LLVMFuzzerTestOneInput_211(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our needs
    if (size < sizeof(size_t) * 6 + sizeof(ptrdiff_t) * 2 + sizeof(int) * 2) {
        return 0;
    }

    // Initialize variables
    int ncid = *(int *)data; // First 4 bytes for ncid
    int varid = *(int *)(data + sizeof(int)); // Next 4 bytes for varid

    // Pointers to size_t arrays
    const size_t *start = (const size_t *)(data + 2 * sizeof(int));
    const size_t *count = (const size_t *)(data + 2 * sizeof(int) + sizeof(size_t) * 2);

    // Pointers to ptrdiff_t arrays
    const ptrdiff_t *stride = (const ptrdiff_t *)(data + 2 * sizeof(int) + sizeof(size_t) * 4);
    const ptrdiff_t *imap = (const ptrdiff_t *)(data + 2 * sizeof(int) + sizeof(size_t) * 4 + sizeof(ptrdiff_t));

    // Pointer to a buffer for data
    void *buffer = (void *)(data + 2 * sizeof(int) + sizeof(size_t) * 4 + sizeof(ptrdiff_t) * 2);

    // Extract valid values for start, count, stride, and imap
    size_t start_val = extract_size_t((const uint8_t *)start);
    size_t count_val = extract_size_t((const uint8_t *)count);
    ptrdiff_t stride_val = extract_ptrdiff_t((const uint8_t *)stride);
    ptrdiff_t imap_val = extract_ptrdiff_t((const uint8_t *)imap);

    // Call the function-under-test with extracted values
    nc_get_varm(ncid, varid, &start_val, &count_val, &stride_val, &imap_val, buffer);

    return 0;
}