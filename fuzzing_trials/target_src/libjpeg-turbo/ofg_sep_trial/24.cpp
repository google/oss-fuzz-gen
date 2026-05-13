#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_24(const uint8_t *data, size_t size) {
    if (size < 1) return 0;

    // Initialize TurboJPEG handle
    tjhandle handle = tjInitCompress();
    if (handle == nullptr) {
        return 0;
    }

    // Define image dimensions and parameters
    int width = 256; // Example width
    int height = 256; // Example height
    int pitch = width * 3; // Assuming RGB format
    int pixelFormat = TJPF_RGB; // Assuming RGB pixel format
    int subsamp = TJSAMP_444; // Example subsampling
    int flags = 0; // No flags

    // Allocate memory for YUV planes
    unsigned char *yuvPlanes[3];
    int strides[3] = { width, width / 2, width / 2 }; // Example strides

    for (int i = 0; i < 3; ++i) {
        yuvPlanes[i] = (unsigned char *)malloc(strides[i] * height);
        if (yuvPlanes[i] == nullptr) {
            tjDestroy(handle);
            return 0;
        }
    }

    // Call the function-under-test with the correct number of arguments
    int result = tjEncodeYUVPlanes(handle, data, width, pitch, height, pixelFormat, yuvPlanes, strides, subsamp, flags);

    // Free allocated memory
    for (int i = 0; i < 3; ++i) {
        free(yuvPlanes[i]);
    }

    // Destroy TurboJPEG handle
    tjDestroy(handle);

    return 0;
}