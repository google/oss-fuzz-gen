#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_357(const uint8_t *data, size_t size) {
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsHPROFILE profile = NULL;

    // Ensure the data is large enough to contain two null-terminated strings
    if (size < 2) {
        cmsDeleteContext(context);
        return 0;
    }

    // Allocate memory for the file name and mode strings
    char *filename = (char *)malloc(size + 1);
    char *mode = (char *)malloc(size + 1);

    // Copy data into filename and mode, ensuring null-termination
    memcpy(filename, data, size);
    filename[size] = '\0';
    memcpy(mode, data, size);
    mode[size] = '\0';

    // Call the function under test
    profile = cmsOpenProfileFromFileTHR(context, filename, mode);

    // Clean up
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }
    cmsDeleteContext(context);
    free(filename);
    free(mode);

    return 0;
}