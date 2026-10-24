#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_150(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    char filename[256];

    // Initialize the handle
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Ensure the filename is null-terminated and not empty
    if (size > 0 && size < sizeof(filename)) {
        memcpy(filename, data, size);
        filename[size] = '\0';

        // Call the function-under-test
        cmsIT8SaveToFile(handle, filename);
    }

    // Free the handle
    cmsIT8Free(handle);

    return 0;
}