#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <lcms2_plugin.h>
#include <lcms2.h> // Include the main Little CMS header for necessary types and functions

int LLVMFuzzerTestOneInput_265(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient for a null-terminated string
    if (size < 1) {
        return 0;
    }

    // Initialize a cmsHANDLE
    cmsHANDLE handle = cmsIT8Alloc(cmsCreateContext(NULL, NULL));
    if (handle == NULL) {
        return 0;
    }

    // Create a null-terminated string from the input data
    char *propertyName = (char *)malloc(size + 1);
    if (propertyName == NULL) {
        cmsIT8Free(handle);
        return 0;
    }
    memcpy(propertyName, data, size);
    propertyName[size] = '\0';

    // Call the function-under-test
    const char *propertyValue = cmsIT8GetProperty(handle, propertyName);

    // Print the property value if it is not NULL (for debugging purposes)
    if (propertyValue != NULL) {
        printf("Property Value: %s\n", propertyValue);
    }

    // Clean up
    free(propertyName);
    cmsIT8Free(handle);

    return 0;
}