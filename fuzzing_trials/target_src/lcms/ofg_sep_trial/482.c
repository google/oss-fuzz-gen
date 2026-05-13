#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_482(const uint8_t *data, size_t size) {
    cmsContext context = NULL; // Assuming a default context
    cmsUInt32Number numColors = 1;
    cmsUInt32Number flags = 0;

    // Ensure data is not empty to create non-NULL strings
    if (size < 2) {
        return 0;
    }

    // Split the data into two parts for the two string parameters
    size_t str1_len = size / 2;
    size_t str2_len = size - str1_len;

    char *prefix = (char *)malloc(str1_len + 1);
    char *suffix = (char *)malloc(str2_len + 1);

    if (prefix == NULL || suffix == NULL) {
        free(prefix);
        free(suffix);
        return 0;
    }

    memcpy(prefix, data, str1_len);
    prefix[str1_len] = '\0';

    memcpy(suffix, data + str1_len, str2_len);
    suffix[str2_len] = '\0';

    // Call the function-under-test
    cmsNAMEDCOLORLIST *namedColorList = cmsAllocNamedColorList(context, numColors, flags, prefix, suffix);

    // Clean up
    if (namedColorList != NULL) {
        cmsFreeNamedColorList(namedColorList);
    }

    free(prefix);
    free(suffix);

    return 0;
}