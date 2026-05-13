#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_51(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    char **formatList = NULL;

    // Initialize the handle using the correct LCMS function
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Call the function under test using the correct LCMS function signature
    int result = cmsIT8EnumDataFormat(handle, &formatList);

    // Cleanup
    if (formatList != NULL) {
        free(formatList); // Free the formatList array
    }
    cmsIT8Free(handle);

    return 0;
}