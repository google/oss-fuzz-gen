#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <lcms2.h>  // Assuming the function is part of the Little CMS library

int LLVMFuzzerTestOneInput_334(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    int row = 0;
    int col = 0;

    // Initialize handle with a valid cmsHANDLE object
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0; // Exit if we cannot allocate handle
    }

    // Ensure row and col are within some reasonable bounds
    if (size > 0) {
        row = data[0] % 10; // Example: Limit row to 0-9
    }
    if (size > 1) {
        col = data[1] % 10; // Example: Limit col to 0-9
    }

    // Call the function-under-test
    const char *result = cmsIT8GetDataRowCol(handle, row, col);

    // For the purpose of fuzzing, we don't need to do anything with the result
    // but we can print it for debugging purposes
    if (result != NULL) {
        printf("Result: %s\n", result);
    }

    // Free the handle
    cmsIT8Free(handle);

    return 0;
}