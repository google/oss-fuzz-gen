#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_103(const uint8_t *data, size_t size) {
    // Ensure the data is large enough to contain a valid file name and mode
    if (size < 2) {
        return 0;
    }

    // Create a temporary file to simulate a profile file
    const char *tempFileName = "temp_profile.icc";
    FILE *tempFile = fopen(tempFileName, "wb");
    if (tempFile == NULL) {
        return 0;
    }
    fwrite(data, 1, size, tempFile);
    fclose(tempFile);

    // Define the mode string
    const char *mode = "r"; // Open the file in read mode

    // Call the function-under-test
    cmsHPROFILE profile = cmsOpenProfileFromFile(tempFileName, mode);

    // Clean up
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }

    // Remove the temporary file
    remove(tempFileName);

    return 0;
}