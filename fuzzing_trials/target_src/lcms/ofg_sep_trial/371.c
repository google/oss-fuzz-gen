#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_371(const uint8_t *data, size_t size) {
    // Ensure there is enough data for a filename
    if (size < 5) {
        return 0;
    }

    // Create a temporary filename from the input data
    char filename[256];
    size_t filename_size = (size < 255) ? size : 255;
    memcpy(filename, data, filename_size);
    filename[filename_size] = '\0';

    // Ensure the filename is valid by replacing any invalid characters
    for (size_t i = 0; i < filename_size; i++) {
        if (filename[i] == '\0' || filename[i] == '/' || filename[i] == '\\') {
            filename[i] = '_';
        }
    }

    // Create a dummy profile for testing
    cmsHPROFILE hProfile = cmsCreate_sRGBProfile();
    if (hProfile == NULL) {
        return 0;
    }

    // Call the function-under-test
    cmsBool result = cmsSaveProfileToFile(hProfile, filename);

    // Clean up
    cmsCloseProfile(hProfile);

    return 0;
}