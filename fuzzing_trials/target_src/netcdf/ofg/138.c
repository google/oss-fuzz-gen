#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Function prototype for the function-under-test
int nc_get_vara_text(int ncid, int varid, const size_t *start, const size_t *count, char *text);

// LLVMFuzzerTestOneInput function
int LLVMFuzzerTestOneInput_138(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for the required parameters
    if (size < sizeof(size_t) * 2 + 2 * sizeof(int) + 1) {
        return 0;
    }

    // Extract parameters from the data
    int ncid = *(const int *)data;
    data += sizeof(int);
    int varid = *(const int *)data;
    data += sizeof(int);

    size_t start[1];
    start[0] = *(const size_t *)data;
    data += sizeof(size_t);

    size_t count[1];
    count[0] = *(const size_t *)data;
    data += sizeof(size_t);

    // Allocate memory for the text output
    size_t text_size = count[0] + 1; // +1 for null terminator
    char *text = (char *)malloc(text_size);
    if (text == NULL) {
        return 0;
    }

    // Initialize the text buffer with non-null values
    memset(text, 'A', text_size - 1);
    text[text_size - 1] = '\0';

    // Call the function-under-test
    nc_get_vara_text(ncid, varid, start, count, text);

    // Free the allocated memory
    free(text);

    return 0;
}