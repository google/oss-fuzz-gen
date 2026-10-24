#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "lcms2_plugin.h" // Assuming this is the correct header for cmsIT8SetSheetType

int LLVMFuzzerTestOneInput_418(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    char *sheetType;

    // Initialize handle with a non-NULL value
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0; // Allocation failed, exit
    }

    // Allocate memory for sheetType and ensure it's null-terminated
    sheetType = (char *)malloc(size + 1);
    if (sheetType == NULL) {
        cmsIT8Free(handle);
        return 0; // Allocation failed, exit
    }

    // Copy data to sheetType and null-terminate
    memcpy(sheetType, data, size);
    sheetType[size] = '\0';

    // Call the function-under-test
    cmsIT8SetSheetType(handle, sheetType);

    // Clean up
    free(sheetType);
    cmsIT8Free(handle);

    return 0;
}