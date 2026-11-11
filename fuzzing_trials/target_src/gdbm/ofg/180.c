#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Assuming the definition of struct pagerfile is available
struct pagerfile {
    // Example fields, actual definition may vary
    char *buffer;
    size_t size;
    size_t capacity;
};

// Mock implementation of pager_putc_180 for demonstration
int pager_putc_180(struct pagerfile *pf, int c) {
    if (pf->size >= pf->capacity) {
        return -1; // Buffer is full
    }
    pf->buffer[pf->size++] = (char)c;
    return 0; // Success
}

int LLVMFuzzerTestOneInput_180(const uint8_t *data, size_t size) {
    // Initialize a pagerfile structure
    struct pagerfile pf;
    pf.capacity = 1024; // Set a capacity for the buffer
    pf.size = 0;
    pf.buffer = (char *)malloc(pf.capacity);
    if (!pf.buffer) {
        return 0; // Exit if memory allocation fails
    }

    // Use the first byte of data as the character to be added
    int c = size > 0 ? data[0] : 'A'; // Default to 'A' if no data

    // Call the function-under-test
    pager_putc_180(&pf, c);

    // Clean up
    free(pf.buffer);

    return 0;
}