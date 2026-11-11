#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <lcms2_plugin.h>

int LLVMFuzzerTestOneInput_164(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    const char *propertyName;
    const char *propertyValue;

    // Ensure size is sufficient to split into two non-empty strings
    if (size < 2) {
        return 0;
    }

    // Initialize handle
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Split the data into two strings
    size_t mid = size / 2;

    // Allocate memory for propertyName and propertyValue
    propertyName = (const char *)malloc(mid + 1);
    propertyValue = (const char *)malloc(size - mid + 1);

    if (propertyName == NULL || propertyValue == NULL) {
        cmsIT8Free(handle);
        free((void *)propertyName);
        free((void *)propertyValue);
        return 0;
    }

    // Copy data into propertyName and propertyValue
    memcpy((void *)propertyName, data, mid);
    memcpy((void *)propertyValue, data + mid, size - mid);

    // Null-terminate the strings
    ((char *)propertyName)[mid] = '\0';
    ((char *)propertyValue)[size - mid] = '\0';

    // Call the function-under-test
    cmsIT8SetPropertyUncooked(handle, propertyName, propertyValue);

    // Clean up
    cmsIT8Free(handle);
    free((void *)propertyName);
    free((void *)propertyValue);

    return 0;
}