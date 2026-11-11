#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_39(const uint8_t *data, size_t size) {
    // Initialize variables for the function parameters
    cmsHANDLE handle;
    const char *propertyName;
    cmsFloat64Number value;

    // Ensure size is sufficient to extract a double and a property name
    if (size < sizeof(cmsFloat64Number) + 1) {
        return 0;
    }

    // Create a dummy handle for testing purposes
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Extract a double value from the data
    memcpy(&value, data, sizeof(cmsFloat64Number));

    // Extract a property name from the data
    propertyName = (const char *)(data + sizeof(cmsFloat64Number));

    // Ensure the property name is null-terminated
    size_t propertyNameLength = strnlen(propertyName, size - sizeof(cmsFloat64Number));
    if (propertyNameLength == size - sizeof(cmsFloat64Number)) {
        cmsIT8Free(handle);
        return 0;
    }

    // Call the function-under-test
    cmsIT8SetPropertyDbl(handle, propertyName, value);

    // Free the allocated handle
    cmsIT8Free(handle);

    return 0;
}