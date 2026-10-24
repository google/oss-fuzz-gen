#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_20(const uint8_t *data, size_t size) {
    tjhandle handle = tjInitCompress();
    if (!handle) {
        return 0;
    }

    // Define and initialize parameters for tjEncodeYUV3
    const unsigned char *srcBuf = data;
    int width = 64;  // Example width
    int height = 64; // Example height
    int pitch = width * 3; // Assuming 3 bytes per pixel for RGB
    int pixelFormat = TJPF_RGB;
    unsigned char *dstBuf = (unsigned char *)malloc(tjBufSizeYUV2(width, 4, height, TJSAMP_420));
    int pad = 4;
    int subsamp = TJSAMP_420;
    int flags = 0;

    if (dstBuf == nullptr) {
        tjDestroy(handle);
        return 0;
    }

    // Call the function-under-test
    tjEncodeYUV3(handle, srcBuf, width, pitch, height, pixelFormat, dstBuf, pad, subsamp, flags);

    // Clean up
    free(dstBuf);
    tjDestroy(handle);

    return 0;
}