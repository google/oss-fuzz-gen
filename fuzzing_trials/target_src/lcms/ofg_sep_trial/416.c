#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_416(const uint8_t *data, size_t size) {
    // Ensure the data is large enough to extract necessary parameters
    if (size < sizeof(cmsTagSignature) + sizeof(cmsUInt32Number)) {
        return 0;
    }

    // Extract cmsTagSignature from the data
    cmsTagSignature tagSignature = *(cmsTagSignature *)data;

    // Extract cmsUInt32Number from the data
    cmsUInt32Number bufferSize = *(cmsUInt32Number *)(data + sizeof(cmsTagSignature));

    // Create a buffer for the tag data
    void *buffer = malloc(bufferSize);
    if (buffer == NULL) {
        return 0;
    }

    // Initialize a dummy profile for testing
    cmsHPROFILE hProfile = cmsCreate_sRGBProfile();
    if (hProfile == NULL) {
        free(buffer);
        return 0;
    }

    // Call the function-under-test
    cmsUInt32Number result = cmsReadRawTag(hProfile, tagSignature, buffer, bufferSize);

    // Clean up
    cmsCloseProfile(hProfile);
    free(buffer);

    return 0;
}