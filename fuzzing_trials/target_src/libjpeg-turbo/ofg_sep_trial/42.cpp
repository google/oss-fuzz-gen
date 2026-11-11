#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_42(const uint8_t *data, size_t size) {
    tjhandle handle = NULL;
    unsigned char *iccProfile = NULL;
    size_t iccProfileSize = 0;

    // Initialize the TurboJPEG decompressor
    handle = tjInitDecompress();
    if (handle == NULL) {
        fprintf(stderr, "Failed to initialize TurboJPEG decompressor\n");
        return 0;
    }

    // Call the function under test
    int result = tj3GetICCProfile(handle, &iccProfile, &iccProfileSize);

    // Check the result and process the ICC profile if successful
    if (result == 0 && iccProfile != NULL && iccProfileSize > 0) {
        // Process the ICC profile data
        // For fuzzing purposes, we can just print the size
        printf("ICC Profile Size: %zu\n", iccProfileSize);

        // Free the ICC profile data if it was allocated
        tjFree(iccProfile);
    }

    // Clean up and destroy the TurboJPEG handle
    tjDestroy(handle);

    return 0;
}