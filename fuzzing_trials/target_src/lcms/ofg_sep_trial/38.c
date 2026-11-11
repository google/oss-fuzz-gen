#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_38(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    char propertyName[256];
    cmsFloat64Number value;

    // Initialize handle
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Ensure propertyName is null-terminated and not empty
    size_t nameLength = size < 255 ? size : 255;
    memcpy(propertyName, data, nameLength);
    propertyName[nameLength] = '\0';

    // Use data to set a value for cmsFloat64Number
    if (size >= sizeof(cmsFloat64Number)) {
        memcpy(&value, data, sizeof(cmsFloat64Number));
    } else {
        value = 1.0; // Default value if not enough data
    }

    // Call the function-under-test
    cmsIT8SetPropertyDbl(handle, propertyName, value);

    // Clean up
    cmsIT8Free(handle);

    return 0;
}