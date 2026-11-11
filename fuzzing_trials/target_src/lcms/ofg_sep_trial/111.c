#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_111(const uint8_t *data, size_t size) {
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsHPROFILE profile = NULL;
    char *filename = NULL;

    // Ensure size is large enough to create a valid string
    if (size < 1) {
        cmsDeleteContext(context);
        return 0;
    }

    // Allocate memory for the filename and ensure it's null-terminated
    filename = (char *)malloc(size + 1);
    if (filename == NULL) {
        cmsDeleteContext(context);
        return 0;
    }

    memcpy(filename, data, size);
    filename[size] = '\0';

    // Call the function-under-test
    profile = cmsCreateDeviceLinkFromCubeFileTHR(context, filename);

    // Clean up
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }

    free(filename);
    cmsDeleteContext(context);

    return 0;
}