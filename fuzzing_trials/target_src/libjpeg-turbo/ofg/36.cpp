#include <stddef.h>
#include <stdint.h>
#include <cstdlib> // for std::malloc and std::free

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_36(const uint8_t *data, size_t size) {
    if (size < 12) { // Ensure there's enough data for meaningful fuzzing
        return 0;
    }

    // Initialize TurboJPEG handle
    tjhandle handle = tjInitCompress();
    if (handle == nullptr) {
        return 0; // Failed to initialize, exit early
    }

    // Define YUV plane pointers
    const unsigned char *yuvPlanes[3];
    int planeSizes[3];
    unsigned char *jpegBuf = nullptr;
    size_t jpegSize = 0;

    // Set up YUV planes
    yuvPlanes[0] = data; // Y plane
    yuvPlanes[1] = data + size / 3; // U plane
    yuvPlanes[2] = data + 2 * size / 3; // V plane

    // Set up plane sizes (assuming 4:2:0 subsampling for simplicity)
    int width = 2; // Minimum width
    int height = 2; // Minimum height
    planeSizes[0] = width * height; // Y plane size
    planeSizes[1] = width * height / 4; // U plane size
    planeSizes[2] = width * height / 4; // V plane size

    // Correct the TJBUFSIZE function call to use the correct number of arguments
    jpegBuf = (unsigned char*)std::malloc(TJBUFSIZE(width, height));
    if (jpegBuf == nullptr) {
        tjDestroy(handle);
        return 0;
    }

    // Ensure tj3CompressFromYUVPlanes8 is called with valid parameters
    if (tjCompressFromYUVPlanes(handle, yuvPlanes, width, planeSizes, height, TJSAMP_420, &jpegBuf, &jpegSize, 100, TJFLAG_FASTDCT) == -1) {
        std::free(jpegBuf);
        tjDestroy(handle);
        return 0;
    }

    // Clean up
    std::free(jpegBuf);
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

    LLVMFuzzerTestOneInput_36(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
