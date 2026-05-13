#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_333(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    int row, col;
    const char *result;

    // Initialize variables
    handle = cmsIT8Alloc(NULL);  // Allocate a new IT8 handle
    if (handle == NULL) {
        return 0; // Return if allocation fails
    }

    // Ensure size is sufficient for extracting row and col
    if (size < sizeof(int) * 2) {
        cmsIT8Free(handle);
        return 0;
    }

    // Extract row and col from data
    row = (int)data[0];
    col = (int)data[1];

    // Call the function-under-test
    result = cmsIT8GetDataRowCol(handle, row, col);

    // Print the result (for debugging purposes)
    if (result != NULL) {
        printf("Result: %s\n", result);
    }

    // Clean up
    cmsIT8Free(handle);

    return 0;
}