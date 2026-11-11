#include <cstddef>
#include <cstdint>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_47(const uint8_t *data, size_t size) {
    tjhandle handle = tjInitDecompress();
    if (!handle) {
        return 0;
    }

    unsigned long jpegSize = static_cast<unsigned long>(size);
    unsigned char *jpegBuf = const_cast<unsigned char *>(data);

    int width = 100;  // Example width
    int height = 100; // Example height
    int pixelFormat = TJPF_RGB; // Example pixel format
    int flags = 0; // No flags set

    unsigned char *dstBuf = new unsigned char[width * height * tjPixelSize[pixelFormat]];

    int result = tjDecompress2(handle, jpegBuf, jpegSize, dstBuf, width, 0, height, pixelFormat, flags);

    tjDestroy(handle);
    delete[] dstBuf;

    return result;
}