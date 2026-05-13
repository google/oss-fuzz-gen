#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_156(const uint8_t *data, size_t size) {
    // Ensure the input size is greater than 0
    if (size == 0) {
        return 0;
    }

    // Allocate memory for the file path and ensure it's null-terminated
    char *filePath = (char *)malloc(size + 1);
    if (filePath == NULL) {
        return 0;
    }

    // Copy the data to the file path and null-terminate it
    memcpy(filePath, data, size);
    filePath[size] = '\0';

    // Call the function-under-test
    cmsHPROFILE profile = cmsCreateDeviceLinkFromCubeFile(filePath);

    // Free the allocated memory
    free(filePath);

    // If the profile is created, release it
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }

    return 0;
}