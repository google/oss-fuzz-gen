#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_240(const uint8_t *data, size_t size) {
    // Ensure the data is large enough to be used for our parameters
    if (size < sizeof(size_t) + 2) {
        return 0;
    }

    // Extract parameters from the data
    int ncid = (int)data[0];  // Use the first byte as ncid
    int varid = (int)data[1]; // Use the second byte as varid

    // Use the next bytes to form a size_t index
    size_t index;
    memcpy(&index, data + 2, sizeof(size_t));

    // Use the remaining bytes as the text data
    const char *text = (const char *)(data + 2 + sizeof(size_t));
    size_t text_len = size - (2 + sizeof(size_t));

    // Ensure the text is null-terminated
    char *text_buffer = (char *)malloc(text_len + 1);
    if (text_buffer == NULL) {
        return 0;
    }
    memcpy(text_buffer, text, text_len);
    text_buffer[text_len] = '\0';

    // Call the function-under-test
    nc_put_var1_text(ncid, varid, &index, text_buffer);

    // Clean up
    free(text_buffer);

    return 0;
}