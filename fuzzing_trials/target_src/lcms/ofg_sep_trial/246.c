#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_246(const uint8_t *data, size_t size) {
    // Initialize variables for the function call
    cmsHANDLE handle;
    int row, col;
    const char *text;

    // Ensure the size is sufficient to extract meaningful data
    if (size < sizeof(int) * 2 + 1) {
        return 0;
    }

    // Allocate a cmsHANDLE object (for simplicity, using a dummy allocation)
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Extract row and col from the input data
    row = *((int *)data);
    col = *((int *)(data + sizeof(int)));

    // Extract text from the remaining data
    text = (const char *)(data + sizeof(int) * 2);

    // Ensure text is null-terminated
    char *nullTerminatedText = (char *)malloc(size - sizeof(int) * 2 + 1);
    if (nullTerminatedText == NULL) {
        cmsIT8Free(handle);
        return 0;
    }
    memcpy(nullTerminatedText, text, size - sizeof(int) * 2);
    nullTerminatedText[size - sizeof(int) * 2] = '\0';

    // Call the function-under-test
    cmsIT8SetDataRowCol(handle, row, col, nullTerminatedText);

    // Free allocated resources
    free(nullTerminatedText);
    cmsIT8Free(handle);

    return 0;
}