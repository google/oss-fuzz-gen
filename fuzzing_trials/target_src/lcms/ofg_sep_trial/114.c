#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_114(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    const char *result;
    
    // Ensure the data is large enough to split into two non-null strings
    if (size < 2) {
        return 0;
    }

    // Create a cmsHANDLE for testing
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Split the input data into two strings
    size_t half_size = size / 2;
    char *str1 = (char *)malloc(half_size + 1);
    char *str2 = (char *)malloc(half_size + 1);

    if (str1 == NULL || str2 == NULL) {
        cmsIT8Free(handle);
        free(str1);
        free(str2);
        return 0;
    }

    memcpy(str1, data, half_size);
    str1[half_size] = '\0';

    memcpy(str2, data + half_size, half_size);
    str2[half_size] = '\0';

    // Call the function-under-test
    result = cmsIT8GetData(handle, str1, str2);

    // Clean up
    cmsIT8Free(handle);
    free(str1);
    free(str2);

    return 0;
}