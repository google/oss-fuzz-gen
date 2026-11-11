#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_110(const uint8_t *data, size_t size) {
    cmsContext context;
    char *filePath;

    // Initialize a non-null cmsContext
    context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    // Ensure size is sufficient to create a valid C string for file path
    if (size < 2) {
        cmsDeleteContext(context);
        return 0;
    }

    // Allocate memory for file path and copy data into it, ensuring null-termination
    filePath = (char *)malloc(size + 1);
    if (filePath == NULL) {
        cmsDeleteContext(context);
        return 0;
    }
    memcpy(filePath, data, size);
    filePath[size] = '\0';

    // Call the function-under-test
    cmsHPROFILE profile = cmsCreateDeviceLinkFromCubeFileTHR(context, filePath);

    // Clean up
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }
    free(filePath);
    cmsDeleteContext(context);

    return 0;
}