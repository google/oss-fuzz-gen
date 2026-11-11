#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_356(const uint8_t *data, size_t size) {
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    // Ensure the input data is null-terminated for use as a C string
    char *filename = (char *)malloc(size + 1);
    if (filename == NULL) {
        cmsDeleteContext(context);
        return 0;
    }
    memcpy(filename, data, size);
    filename[size] = '\0';

    // Use a fixed mode for opening the file
    const char *mode = "r";

    // Call the function-under-test
    cmsHPROFILE profile = cmsOpenProfileFromFileTHR(context, filename, mode);

    // Clean up
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }
    free(filename);
    cmsDeleteContext(context);

    return 0;
}