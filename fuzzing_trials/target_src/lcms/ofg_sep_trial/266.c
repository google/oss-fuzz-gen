#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_266(const uint8_t *data, size_t size) {
    // Ensure we have enough data to work with
    if (size < 2) return 0;

    // Initialize a cmsHANDLE
    cmsHANDLE handle = cmsIT8Alloc(NULL);
    if (handle == NULL) return 0;

    // Use part of the data as a property name
    size_t propNameLen = size - 1; // Ensure at least 1 character
    char *propertyName = (char *)malloc(propNameLen + 1);
    if (propertyName == NULL) {
        cmsIT8Free(handle);
        return 0;
    }
    memcpy(propertyName, data, propNameLen);
    propertyName[propNameLen] = '\0';

    // Call the function-under-test
    const char *propertyValue = cmsIT8GetProperty(handle, propertyName);

    // Clean up
    free(propertyName);
    cmsIT8Free(handle);

    return 0;
}