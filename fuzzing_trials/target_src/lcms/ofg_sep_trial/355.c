#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_355(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    char **properties = NULL;
    cmsUInt32Number result;
    
    // Initialize the handle with a default context
    handle = cmsIT8LoadFromMem(NULL, data, size);
    if (handle == NULL) {
        return 0;
    }

    // Call the function-under-test
    result = cmsIT8EnumProperties(handle, &properties);

    // Clean up
    if (properties != NULL) {
        for (cmsUInt32Number i = 0; i < result; i++) {
            if (properties[i] != NULL) {
                free(properties[i]);
            }
        }
        free(properties);
    }
    cmsIT8Free(handle);

    return 0;
}