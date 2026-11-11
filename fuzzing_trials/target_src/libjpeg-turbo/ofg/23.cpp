#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_23(const uint8_t *data, size_t size) {
    if (size < 3) {
        return 0; // Not enough data to proceed
    }

    // Initialize tjhandle
    tjhandle handle = tj3Init(TJINIT_COMPRESS);
    if (handle == nullptr) {
        return 0; // Failed to initialize handle
    }

    // Extract width, height, and subsampling from the data
    int width = data[0] + 1; // Ensure width is at least 1
    int height = data[1] + 1; // Ensure height is at least 1
    int subsampling = data[2] % 3; // Use a valid subsampling value

    // Calculate the minimum size of YUV buffer
    int yuvSize = tj3YUVBufSize(width, 1, height, subsampling); // Added alignment parameter
    if (size < 3 + yuvSize) {
        tj3Destroy(handle);
        return 0; // Not enough data for the YUV buffer
    }

    // Prepare YUV buffer
    const unsigned char *yuvBuffer = data + 3;

    // Prepare output buffer
    unsigned char *jpegBuf = nullptr;
    size_t jpegSize = 0;

    // Set some parameters to ensure non-trivial processing
    tj3Set(handle, TJPARAM_QUALITY, 75); // Set JPEG quality to a reasonable value
    tj3Set(handle, TJPARAM_SUBSAMP, subsampling); // Set subsampling

    // Call the function-under-test
    int result = tj3CompressFromYUV8(handle, yuvBuffer, width, 1, height, &jpegBuf, &jpegSize);

    // Clean up
    if (jpegBuf != nullptr) {
        tj3Free(jpegBuf);
    }
    tj3Destroy(handle);

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

    LLVMFuzzerTestOneInput_23(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
