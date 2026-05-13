#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_49(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsHPROFILE hProfile = NULL;
    void *memoryBuffer = NULL;
    cmsUInt32Number bufferSize = 0;

    // Check if the input size is large enough to create a profile
    if (size < sizeof(cmsHPROFILE)) {
        return 0;
    }

    // Create a profile from the input data
    hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0;
    }

    // Allocate memory for the buffer
    memoryBuffer = malloc(size);
    if (memoryBuffer == NULL) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Attempt to save the profile to memory
    cmsBool result = cmsSaveProfileToMem(hProfile, memoryBuffer, &bufferSize);

    // Clean up
    free(memoryBuffer);
    cmsCloseProfile(hProfile);

    return 0;
}