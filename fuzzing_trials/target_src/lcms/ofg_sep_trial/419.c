#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2_plugin.h>

int LLVMFuzzerTestOneInput_419(const uint8_t *data, size_t size) {
    // Initialize variables for the function call
    cmsHANDLE handle;
    char *sheetType;

    // Ensure size is sufficient for a null-terminated string
    if (size < 1) {
        return 0;
    }

    // Allocate memory for sheetType and ensure it is null-terminated
    sheetType = (char *)malloc(size + 1);
    if (sheetType == NULL) {
        return 0;
    }
    memcpy(sheetType, data, size);
    sheetType[size] = '\0';

    // Initialize handle with a non-NULL value
    handle = cmsIT8Alloc(NULL);
    if (handle != NULL) {
        // Call the function under test
        cmsIT8SetSheetType(handle, sheetType);

        // Free the handle after use
        cmsIT8Free(handle);
    }

    // Free allocated memory for sheetType
    free(sheetType);

    return 0;
}