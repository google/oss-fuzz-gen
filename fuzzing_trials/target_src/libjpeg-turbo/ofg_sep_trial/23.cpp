#include <stdint.h>
#include <stdlib.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_23(const uint8_t *data, size_t size) {
    if (size < 10) {
        // Ensure there's enough data for the parameters
        return 0;
    }

    // Initialize tjhandle
    tjhandle handle = tjInitCompress();
    if (handle == nullptr) {
        return 0;
    }

    // Define and initialize parameters for tjEncodeYUVPlanes
    const unsigned char *srcBuf = data;
    int width = 10; // Arbitrary non-zero width
    int height = 10; // Arbitrary non-zero height
    int pitch = width * 3; // Assuming 3 bytes per pixel for RGB
    int pixelFormat = TJPF_RGB; // Define a valid pixel format
    int subsamp = TJSAMP_444; // Use a valid subsampling option
    unsigned char *dstPlanes[3]; // Y, U, V planes
    int strides[3] = { width, width / 2, width / 2 }; // Example strides for YUV 4:4:4
    int flags = 0; // No flags

    // Allocate memory for Y, U, V planes
    for (int i = 0; i < 3; i++) {
        dstPlanes[i] = (unsigned char *)malloc(width * height);
        if (dstPlanes[i] == nullptr) {
            tjDestroy(handle);
            return 0;
        }
    }

    // Call the function-under-test with the correct number of arguments
    int result = tjEncodeYUVPlanes(handle, srcBuf, width, pitch, height, pixelFormat, dstPlanes, strides, subsamp, flags);

    // Free allocated memory
    for (int i = 0; i < 3; i++) {
        free(dstPlanes[i]);
    }

    // Clean up
    tjDestroy(handle);

    return 0;
}