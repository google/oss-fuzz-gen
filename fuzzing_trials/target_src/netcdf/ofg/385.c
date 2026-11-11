#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Assume this is part of the library being tested
int nc_put_vara_text(int ncid, int varid, const size_t *start, const size_t *count, const char *text);

int LLVMFuzzerTestOneInput_385(const uint8_t *data, size_t size) {
    // Check if size is sufficient to extract parameters
    if (size < 4 * sizeof(size_t) + 2 * sizeof(int) + 1) {
        return 0;
    }

    // Extract parameters from the data
    int ncid = *((int *)data);
    int varid = *((int *)(data + sizeof(int)));
    size_t start[2];
    size_t count[2];
    start[0] = *((size_t *)(data + 2 * sizeof(int)));
    start[1] = *((size_t *)(data + 2 * sizeof(int) + sizeof(size_t)));
    count[0] = *((size_t *)(data + 2 * sizeof(int) + 2 * sizeof(size_t)));
    count[1] = *((size_t *)(data + 2 * sizeof(int) + 3 * sizeof(size_t)));

    // Ensure text is null-terminated and not empty
    size_t text_size = size - (2 * sizeof(int) + 4 * sizeof(size_t));
    if (text_size == 0) {
        return 0;
    }

    char *text = (char *)malloc(text_size + 1);
    if (text == NULL) {
        return 0;
    }
    memcpy(text, data + 2 * sizeof(int) + 4 * sizeof(size_t), text_size);
    text[text_size] = '\0';

    // Validate start and count to ensure they are within a reasonable range
    // Assuming some arbitrary reasonable maximum value for demonstration purposes
    const size_t reasonable_max = 1000;
    if (start[0] >= reasonable_max || start[1] >= reasonable_max || 
        count[0] >= reasonable_max || count[1] >= reasonable_max) {
        free(text);
        return 0;
    }

    // Call the function-under-test
    nc_put_vara_text(ncid, varid, start, count, text);

    // Clean up
    free(text);

    return 0;
}