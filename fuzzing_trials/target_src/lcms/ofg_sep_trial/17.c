#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_17(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsHANDLE handle;
    char *propertyName;
    cmsFloat64Number result;

    // Ensure size is sufficient for a null-terminated string
    if (size < 1) return 0;

    // Create a dummy handle for testing
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) return 0;

    // Allocate memory for the property name and ensure it's null-terminated
    propertyName = (char *)malloc(size + 1);
    if (propertyName == NULL) {
        cmsIT8Free(handle);
        return 0;
    }
    memcpy(propertyName, data, size);
    propertyName[size] = '\0';

    // Call the function-under-test
    result = cmsIT8GetPropertyDbl(handle, propertyName);

    // Clean up
    free(propertyName);
    cmsIT8Free(handle);

    return 0;
}