#include <stdint.h>
#include <stdlib.h>
#include <lcms2_plugin.h>

int LLVMFuzzerTestOneInput_242(const uint8_t *data, size_t size) {
    // Initialize a cmsHANDLE with some non-NULL value.
    cmsHANDLE handle = cmsIT8Alloc(NULL);

    // Ensure the handle is valid before proceeding.
    if (handle == NULL) {
        return 0;
    }

    // Call the function-under-test.
    const char *sheetType = cmsIT8GetSheetType(handle);

    // Free the allocated handle.
    cmsIT8Free(handle);

    return 0;
}