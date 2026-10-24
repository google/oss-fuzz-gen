#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2_plugin.h>
#include <lcms2.h> // Include the main Little CMS library

int LLVMFuzzerTestOneInput_284(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for null-terminated strings
    if (size < 3) {
        return 0;
    }

    // Initialize the cmsHANDLE
    cmsHANDLE handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Prepare strings for the function parameters
    char *set = (char *)malloc(size / 2 + 1);
    char *field = (char *)malloc(size / 2 + 1);

    if (set == NULL || field == NULL) {
        cmsIT8Free(handle);
        free(set);
        free(field);
        return 0;
    }

    // Copy data into strings and null-terminate them
    memcpy(set, data, size / 2);
    set[size / 2] = '\0';

    memcpy(field, data + size / 2, size / 2);
    field[size / 2] = '\0';

    // Call the function-under-test
    cmsFloat64Number result = cmsIT8GetDataDbl(handle, set, field);

    // Clean up
    cmsIT8Free(handle);
    free(set);
    free(field);

    return 0;
}