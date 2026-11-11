#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_466(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to extract strings
    if (size < 3) {
        return 0;
    }

    // Create a memory context for lcms
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    // Create a handle for IT8 data
    cmsHANDLE handle = cmsIT8Alloc(context);
    if (handle == NULL) {
        cmsDeleteContext(context);
        return 0;
    }

    // Extract three non-null strings from the input data
    size_t str1_len = data[0] % (size - 2) + 1;
    size_t str2_len = data[1] % (size - 1 - str1_len) + 1;
    size_t str3_len = data[2] % (size - str1_len - str2_len) + 1;

    char *str1 = (char *)malloc(str1_len + 1);
    char *str2 = (char *)malloc(str2_len + 1);
    char *str3 = (char *)malloc(str3_len + 1);

    if (str1 == NULL || str2 == NULL || str3 == NULL) {
        free(str1);
        free(str2);
        free(str3);
        cmsIT8Free(handle);
        cmsDeleteContext(context);
        return 0;
    }

    memcpy(str1, data + 3, str1_len);
    memcpy(str2, data + 3 + str1_len, str2_len);
    memcpy(str3, data + 3 + str1_len + str2_len, str3_len);

    str1[str1_len] = '\0';
    str2[str2_len] = '\0';
    str3[str3_len] = '\0';

    // Call the function under test
    cmsIT8SetTableByLabel(handle, str1, str2, str3);

    // Clean up
    free(str1);
    free(str2);
    free(str3);
    cmsIT8Free(handle);
    cmsDeleteContext(context);

    return 0;
}