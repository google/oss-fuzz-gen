#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_50(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile;
    void *memBuffer;
    cmsUInt32Number bufferSize;
    cmsBool result;

    // Initialize the memory buffer
    memBuffer = malloc(size);
    if (memBuffer == NULL) {
        return 0;
    }

    // Copy the input data to the memory buffer
    memcpy(memBuffer, data, size);

    // Create a profile from the input data
    hProfile = cmsOpenProfileFromMem(memBuffer, size);
    if (hProfile == NULL) {
        free(memBuffer);
        return 0;
    }

    // Initialize the bufferSize to a non-zero value
    bufferSize = size;

    // Call the function under test
    result = cmsSaveProfileToMem(hProfile, memBuffer, &bufferSize);

    // Clean up
    cmsCloseProfile(hProfile);
    free(memBuffer);

    return 0;
}