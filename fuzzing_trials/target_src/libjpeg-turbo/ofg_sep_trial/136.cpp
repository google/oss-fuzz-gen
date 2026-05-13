#include <stddef.h>
#include <stdint.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_136(const uint8_t *data, size_t size) {
    tjhandle handle = tjInitCompress(); // Initialize a TurboJPEG compressor handle

    if (handle != NULL) {
        // Call the function-under-test
        char *errorStr = tj3GetErrorStr(handle);

        // Ensure the error string is not NULL
        if (errorStr != NULL) {
            // Optionally, print or log the error string for debugging
            // printf("Error: %s\n", errorStr);
        }

        // Clean up the TurboJPEG handle
        tjDestroy(handle);
    }

    return 0;
}