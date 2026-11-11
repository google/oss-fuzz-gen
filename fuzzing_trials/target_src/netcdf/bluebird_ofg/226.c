#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Function-under-test declaration
int nc_get_var1_text(int ncid, int varid, const size_t *indexp, char *text);

// Fuzzing harness
int LLVMFuzzerTestOneInput_226(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract required parameters
    if (size < sizeof(int) * 2 + sizeof(size_t)) {
        return 0;
    }

    // Extract parameters from data
    int ncid = *((int *)data);
    int varid = *((int *)(data + sizeof(int)));
    const size_t *indexp = (const size_t *)(data + 2 * sizeof(int));

    // Allocate memory for the text buffer
    size_t text_size = size - (2 * sizeof(int) + sizeof(size_t));
    char *text = (char *)malloc(text_size + 1); // +1 for null-terminator

    // Ensure allocation was successful
    if (text == NULL) {
        return 0;
    }

    // Copy remaining data into the text buffer and null-terminate it
    memcpy(text, data + 2 * sizeof(int) + sizeof(size_t), text_size);
    text[text_size] = '\0';

    // Call the function-under-test
    nc_get_var1_text(ncid, varid, indexp, text);

    // Free allocated memory
    free(text);

    return 0;
}