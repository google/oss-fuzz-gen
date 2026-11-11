#include <stdint.h>
#include <stdlib.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_26(const uint8_t *data, size_t size) {
    // Initialize variables for tjCompressFromYUVPlanes
    tjhandle handle = tjInitCompress();
    if (handle == nullptr) {
        return 0;
    }

    const unsigned char *srcPlanes[3] = {nullptr, nullptr, nullptr};
    int width = 2;  // Minimum width
    int strides[3] = {width, width / 2, width / 2}; // Assuming YUV 4:2:0 format
    int height = 2; // Minimum height
    int subsamp = TJSAMP_420; // Common YUV subsampling
    unsigned char *jpegBuf = nullptr;
    unsigned long jpegSize = 0;
    int jpegQual = 75; // Typical JPEG quality
    int flags = 0; // No flags

    // Ensure data is large enough to fill the YUV planes
    if (size < width * height * 3 / 2) {
        tjDestroy(handle);
        return 0;
    }

    // Assign data to YUV planes
    srcPlanes[0] = data;
    srcPlanes[1] = data + width * height;
    srcPlanes[2] = data + width * height + (width / 2) * (height / 2);

    // Call the function under test
    int result = tjCompressFromYUVPlanes(handle, srcPlanes, width, strides, height, subsamp, &jpegBuf, &jpegSize, jpegQual, flags);

    // Clean up
    if (jpegBuf != nullptr) {
        tjFree(jpegBuf);
    }
    tjDestroy(handle);

    return 0;
}