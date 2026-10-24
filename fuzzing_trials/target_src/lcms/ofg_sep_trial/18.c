#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <lcms2_plugin.h>

int LLVMFuzzerTestOneInput_18(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    char propertyName[256];
    cmsFloat64Number result;

    // Initialize the handle with a dummy non-NULL value
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Ensure the propertyName is null-terminated and non-NULL
    if (size > 0) {
        size_t len = (size < sizeof(propertyName) - 1) ? size : sizeof(propertyName) - 1;
        memcpy(propertyName, data, len);
        propertyName[len] = '\0';
    } else {
        strcpy(propertyName, "DefaultProperty");
    }

    // Call the function-under-test
    result = cmsIT8GetPropertyDbl(handle, propertyName);

    // Clean up
    cmsIT8Free(handle);

    return 0;
}