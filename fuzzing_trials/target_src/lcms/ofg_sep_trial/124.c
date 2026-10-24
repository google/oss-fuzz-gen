#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <lcms2_plugin.h>

int LLVMFuzzerTestOneInput_124(const uint8_t *data, size_t size) {
    // Initialize parameters for cmsIT8SetPropertyStr
    cmsHANDLE handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Ensure size is sufficient for two null-terminated strings
    if (size < 4) {
        cmsIT8Free(handle);
        return 0;
    }

    // Split the data into two strings
    size_t half_size = size / 2;
    char *property = (char *)malloc(half_size + 1);
    char *value = (char *)malloc(size - half_size + 1);

    if (property == NULL || value == NULL) {
        free(property);
        free(value);
        cmsIT8Free(handle);
        return 0;
    }

    memcpy(property, data, half_size);
    property[half_size] = '\0';

    memcpy(value, data + half_size, size - half_size);
    value[size - half_size] = '\0';

    // Call the function-under-test
    cmsIT8SetPropertyStr(handle, property, value);

    // Cleanup
    free(property);
    free(value);
    cmsIT8Free(handle);

    return 0;
}