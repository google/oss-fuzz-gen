#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_121(const uint8_t *data, size_t size) {
    if (size < 10) {
        return 0; // Ensure there is enough data for the parameters
    }

    // Initialize parameters for tjCompress
    tjhandle handle = tjInitCompress();
    if (handle == NULL) {
        return 0; // Handle initialization failure
    }

    unsigned char *srcBuf = (unsigned char *)malloc(size);
    if (srcBuf == NULL) {
        tjDestroy(handle);
        return 0; // Memory allocation failure
    }
    memcpy(srcBuf, data, size);

    int width = 100; // Example width
    int height = 100; // Example height
    int pixelFormat = TJPF_RGB; // Example pixel format
    int pitch = width * tjPixelSize[pixelFormat];

    unsigned char *jpegBuf = NULL;
    unsigned long jpegSize = 0;
    int jpegSubsamp = TJSAMP_444; // Example subsampling
    int jpegQual = 75; // Example quality
    int flags = 0; // Example flags

    // Call the function-under-test
    int result = tjCompress(handle, srcBuf, width, pitch, height, pixelFormat, jpegBuf, &jpegSize, jpegSubsamp, jpegQual, flags);

    // Clean up
    if (jpegBuf != NULL) {
        tjFree(jpegBuf);
    }
    free(srcBuf);
    tjDestroy(handle);

    return 0;
}