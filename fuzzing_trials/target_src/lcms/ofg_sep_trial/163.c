#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_163(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    char *propertyName;
    char *propertyValue;
    cmsBool result;

    // Ensure the input size is sufficient for splitting into at least two non-empty strings
    if (size < 2) return 0;

    // Allocate memory for propertyName and propertyValue
    propertyName = (char *)malloc(size / 2 + 1);
    propertyValue = (char *)malloc(size / 2 + 1);

    if (propertyName == NULL || propertyValue == NULL) {
        free(propertyName);
        free(propertyValue);
        return 0;
    }

    // Split the input data into two strings for propertyName and propertyValue
    memcpy(propertyName, data, size / 2);
    propertyName[size / 2] = '\0';
    memcpy(propertyValue, data + size / 2, size / 2);
    propertyValue[size / 2] = '\0';

    // Create a dummy handle for testing
    handle = cmsIT8Alloc(NULL);

    if (handle != NULL) {
        // Call the function-under-test
        result = cmsIT8SetPropertyUncooked(handle, propertyName, propertyValue);

        // Free the handle after use
        cmsIT8Free(handle);
    }

    // Free allocated memory
    free(propertyName);
    free(propertyValue);

    return 0;
}