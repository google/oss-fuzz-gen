#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_129(const uint8_t *data, size_t size) {
    // Initialize cmsHANDLE
    cmsHANDLE handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Ensure that the input data is null-terminated
    char *formatString = (char *)malloc(size + 1);
    if (formatString == NULL) {
        cmsIT8Free(handle);
        return 0;
    }
    memcpy(formatString, data, size);
    formatString[size] = '\0';

    // Call the function-under-test
    cmsIT8DefineDblFormat(handle, formatString);

    // Clean up
    free(formatString);
    cmsIT8Free(handle);

    return 0;
}