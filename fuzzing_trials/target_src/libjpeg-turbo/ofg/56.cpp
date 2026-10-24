#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_56(const uint8_t *data, size_t size) {
    if (size < 10) return 0; // Ensure there's enough data for basic parameters

    // Initialize TurboJPEG handle
    tjhandle handle = tjInitCompress();
    if (handle == nullptr) return 0;

    // Prepare YUV planes
    const unsigned char *yuvPlanes[3];
    int yuvStrides[3];
    int width = 2; // Minimum width
    int height = 2; // Minimum height
    int subsamp = TJSAMP_444; // Default subsampling

    // Ensure data is enough to fill the YUV planes
    if (size < width * height * 3) {
        tjDestroy(handle);
        return 0;
    }

    yuvPlanes[0] = data; // Y plane
    yuvPlanes[1] = data + width * height; // U plane
    yuvPlanes[2] = data + width * height * 2; // V plane

    yuvStrides[0] = width;
    yuvStrides[1] = width / 2;
    yuvStrides[2] = width / 2;

    // Prepare output buffer
    unsigned char *jpegBuf = nullptr;
    unsigned long jpegSize = 0;

    // Call the function-under-test
    int result = tjCompressFromYUVPlanes(
        handle,
        yuvPlanes,
        width,
        yuvStrides,
        height,
        subsamp,
        &jpegBuf,
        &jpegSize,
        TJSAMP_444,
        TJFLAG_FASTDCT
    );

    // Free the JPEG buffer if it was allocated
    if (jpegBuf != nullptr) {
        tjFree(jpegBuf);
    }

    // Destroy the TurboJPEG handle
    tjDestroy(handle);

    return 0;
}
#ifdef INC_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc, char *argv[])
{
    FILE *f;
    uint8_t *data = NULL;
    long size;

    if(argc < 2)
        exit(0);

    f = fopen(argv[1], "rb");
    if(f == NULL)
        exit(0);

    fseek(f, 0, SEEK_END);

    size = ftell(f);
    rewind(f);

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_56(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
