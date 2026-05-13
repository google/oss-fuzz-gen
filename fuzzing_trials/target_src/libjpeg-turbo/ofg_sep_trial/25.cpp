#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_25(const uint8_t *data, size_t size) {
    tjhandle handle = tjInitCompress();
    if (handle == NULL) {
        return 0;
    }

    const unsigned char *yuvPlanes[3] = {data, data, data};
    int strides[3] = {0, 0, 0};
    int width = 1;  // Minimal valid width
    int height = 1; // Minimal valid height
    int subsamp = TJSAMP_444; // Using a valid subsampling option
    unsigned char *jpegBuf = NULL;
    unsigned long jpegSize = 0;
    int jpegQual = 75; // Typical JPEG quality
    int flags = 0;

    // Correct the function call by removing the extra 'width' argument
    tjCompressFromYUVPlanes(handle, yuvPlanes, width, strides, height, subsamp, &jpegBuf, &jpegSize, jpegQual, flags);

    // Clean up
    tjFree(jpegBuf);
    tjDestroy(handle);

    return 0;
}