#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_468(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient for creating strings
    if (size < 3) {
        return 0;
    }

    // Initialize a fake cmsHANDLE
    cmsHANDLE handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Split the input data into two parts for the strings
    size_t str1_len = size / 3;
    size_t str2_len = size / 3;
    size_t str3_len = size - str1_len - str2_len;

    // Allocate and copy strings from the data
    char *str1 = (char *)malloc(str1_len + 1);
    char *str2 = (char *)malloc(str2_len + 1);
    char *str3 = (char *)malloc(str3_len + 1);

    if (str1 == NULL || str2 == NULL || str3 == NULL) {
        cmsIT8Free(handle);
        free(str1);
        free(str2);
        free(str3);
        return 0;
    }

    memcpy(str1, data, str1_len);
    str1[str1_len] = '\0';

    memcpy(str2, data + str1_len, str2_len);
    str2[str2_len] = '\0';

    memcpy(str3, data + str1_len + str2_len, str3_len);
    str3[str3_len] = '\0';

    // Call the function under test
    const char *result = cmsIT8GetPropertyMulti(handle, str1, str2);

    // Free allocated resources
    cmsIT8Free(handle);
    free(str1);
    free(str2);
    free(str3);

    // Use the result in some way to avoid optimization issues
    if (result != NULL) {
        (void)strlen(result);
    }

    return 0;
}