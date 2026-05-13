#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_44(const uint8_t *data, size_t size) {
    tjhandle handle = tjInitDecompress();
    if (handle == nullptr) {
        return 0;
    }

    unsigned char *jpegBuf = const_cast<unsigned char *>(data);
    unsigned long jpegSize = static_cast<unsigned long>(size);

    int width = 1;  // Initialize with a non-zero value
    int height = 1; // Initialize with a non-zero value
    int jpegSubsamp = TJSAMP_444; // Use a valid subsampling value
    int jpegColorspace = TJCS_RGB; // Use a valid colorspace value

    // Get the JPEG header to determine width and height
    if (tjDecompressHeader2(handle, jpegBuf, jpegSize, &width, &height, &jpegSubsamp) != 0) {
        tjDestroy(handle);
        return 0;
    }

    int pixelFormat = TJPF_RGB; // Use a valid pixel format
    unsigned char *dstBuf = (unsigned char *)malloc(width * height * tjPixelSize[pixelFormat]);
    if (dstBuf == nullptr) {
        tjDestroy(handle);
        return 0;
    }

    // Call the function-under-test
    tjDecompress(handle, jpegBuf, jpegSize, dstBuf, width, 0, height, pixelFormat, 0);

    // Cleanup
    free(dstBuf);
    tjDestroy(handle);

    return 0;
}