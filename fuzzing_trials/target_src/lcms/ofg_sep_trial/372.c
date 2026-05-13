#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_372(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for creating a valid string for filename
    if (size < 5) {
        return 0;
    }

    // Create a temporary profile
    cmsHPROFILE hProfile = cmsCreate_sRGBProfile();
    if (hProfile == NULL) {
        return 0;
    }

    // Create a filename from the input data, ensuring it is null-terminated
    char filename[256];
    size_t filename_length = (size < 255) ? size : 255;
    memcpy(filename, data, filename_length);
    filename[filename_length] = '\0';

    // Call the function-under-test
    cmsBool result = cmsSaveProfileToFile(hProfile, filename);

    // Clean up
    cmsCloseProfile(hProfile);

    return 0;
}