#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_364(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for splitting into multiple strings
    if (size < 4) return 0;

    // Allocate memory for the strings and ensure they are null-terminated
    char *str1 = (char *)malloc(size / 4 + 1);
    char *str2 = (char *)malloc(size / 4 + 1);
    char *str3 = (char *)malloc(size / 4 + 1);
    char *str4 = (char *)malloc(size / 4 + 1);

    if (!str1 || !str2 || !str3 || !str4) {
        free(str1);
        free(str2);
        free(str3);
        free(str4);
        return 0;
    }

    memcpy(str1, data, size / 4);
    str1[size / 4] = '\0';
    memcpy(str2, data + size / 4, size / 4);
    str2[size / 4] = '\0';
    memcpy(str3, data + 2 * (size / 4), size / 4);
    str3[size / 4] = '\0';
    memcpy(str4, data + 3 * (size / 4), size / 4);
    str4[size / 4] = '\0';

    // Create a dummy cmsHANDLE
    cmsHANDLE handle = cmsIT8Alloc(NULL);
    if (handle) {
        // Call the function under test
        cmsIT8SetPropertyMulti(handle, str1, str2, str3);

        // Free the handle
        cmsIT8Free(handle);
    }

    // Free allocated memory
    free(str1);
    free(str2);
    free(str3);
    free(str4);

    return 0;
}