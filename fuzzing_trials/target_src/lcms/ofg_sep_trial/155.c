#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_155(const uint8_t *data, size_t size) {
    // Ensure the input data is null-terminated and non-empty
    if (size == 0) {
        return 0;
    }

    // Allocate memory for the file path and copy the data into it
    char *filePath = (char *)malloc(size + 1);
    if (filePath == NULL) {
        return 0;
    }
    memcpy(filePath, data, size);
    filePath[size] = '\0';  // Null-terminate the string

    // Call the function-under-test
    cmsHPROFILE profile = cmsCreateDeviceLinkFromCubeFile(filePath);

    // Clean up
    free(filePath);

    // If a valid profile was created, release it
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }

    return 0;
}