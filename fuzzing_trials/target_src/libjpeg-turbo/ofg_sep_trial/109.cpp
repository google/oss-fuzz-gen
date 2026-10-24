#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_109(const uint8_t *data, size_t size) {
    tjhandle handle = tj3Init(TJINIT_DECOMPRESS);
    if (handle == NULL) {
        return 0;
    }

    // Assuming a reasonable width and height for YUV image
    int width = 128;
    int height = 128;
    // Use TJSAMP_444 for YUV sampling format
    int align = 1; // Assuming no specific alignment is needed
    int yuvSize = tj3YUVBufSize(width, align, height, TJSAMP_444);

    // Allocate buffer for YUV output
    unsigned char *yuvBuffer = new unsigned char[yuvSize];
    if (yuvBuffer == NULL) {
        tj3Destroy(handle);
        return 0;
    }

    // Call the function-under-test
    int result = tj3DecompressToYUV8(handle, data, size, yuvBuffer, 0);

    // Clean up
    delete[] yuvBuffer;
    tj3Destroy(handle);

    return 0;
}