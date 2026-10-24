#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_235(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    char *propertyName;
    cmsUInt32Number value;

    if (size < sizeof(cmsUInt32Number) + 1) {
        return 0; // Not enough data to proceed
    }

    // Initialize the handle with a dummy value
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0; // Allocation failed
    }

    // Extract a cmsUInt32Number from the data
    memcpy(&value, data, sizeof(cmsUInt32Number));
    data += sizeof(cmsUInt32Number);
    size -= sizeof(cmsUInt32Number);

    // Allocate memory for propertyName and copy from data
    propertyName = (char *)malloc(size + 1);
    if (propertyName == NULL) {
        cmsIT8Free(handle);
        return 0; // Memory allocation failed
    }
    memcpy(propertyName, data, size);
    propertyName[size] = '\0'; // Null-terminate the string

    // Call the function-under-test
    cmsIT8SetPropertyHex(handle, propertyName, value);

    // Clean up
    free(propertyName);
    cmsIT8Free(handle);

    return 0;
}