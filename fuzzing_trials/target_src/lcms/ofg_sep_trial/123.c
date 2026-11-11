#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_123(const uint8_t *data, size_t size) {
    // Initialize the parameters for cmsIT8SetPropertyStr
    cmsHANDLE handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Ensure we have enough data to create two strings
    if (size < 2) {
        cmsIT8Free(handle);
        return 0;
    }

    // Split the data into two parts for the two string parameters
    size_t half_size = size / 2;
    char *propertyName = (char *)malloc(half_size + 1);
    char *propertyValue = (char *)malloc(size - half_size + 1);

    if (!propertyName || !propertyValue) {
        free(propertyName);
        free(propertyValue);
        cmsIT8Free(handle);
        return 0;
    }

    // Copy the data into the strings and null-terminate them
    memcpy(propertyName, data, half_size);
    propertyName[half_size] = '\0';

    memcpy(propertyValue, data + half_size, size - half_size);
    propertyValue[size - half_size] = '\0';

    // Call the function-under-test
    cmsBool result = cmsIT8SetPropertyStr(handle, propertyName, propertyValue);

    // Clean up
    free(propertyName);
    free(propertyValue);
    cmsIT8Free(handle);

    return 0;
}