#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_245(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    int row, col;
    const char *text;

    // Initialize handle
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Ensure size is sufficient for extracting row, col, and text
    if (size < sizeof(int) * 2 + 1) {
        cmsIT8Free(handle);
        return 0;
    }

    // Extract row and col from the data
    row = (int)data[0];
    col = (int)data[1];

    // Ensure text is null-terminated
    text = (const char *)(data + sizeof(int) * 2);
    size_t text_length = size - sizeof(int) * 2;
    char *null_terminated_text = (char *)malloc(text_length + 1);
    if (null_terminated_text == NULL) {
        cmsIT8Free(handle);
        return 0;
    }
    memcpy(null_terminated_text, text, text_length);
    null_terminated_text[text_length] = '\0';

    // Call the function under test
    cmsBool result = cmsIT8SetDataRowCol(handle, row, col, null_terminated_text);

    // Clean up
    free(null_terminated_text);
    cmsIT8Free(handle);

    return 0;
}