#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_70(const uint8_t *data, size_t size) {
    if (size < 6) {
        return 0; // Ensure there's enough data for width, height, and subsampling
    }

    // Initialize tjhandle
    tjhandle handle = tj3Init(TJINIT_COMPRESS);
    if (handle == nullptr) {
        return 0;
    }

    // Extract width, height, and subsampling from the input data
    int width = data[0] + 1;  // Ensure width is at least 1
    int height = data[1] + 1; // Ensure height is at least 1
    int subsamp = data[2] % 5; // Valid subsampling options are 0 to 4

    // Calculate the size of the YUV buffer
    int yuvSize = tj3YUVBufSize(width, 1, height, subsamp); // Align parameter added
    if (yuvSize < 0) {
        tj3Destroy(handle);
        return 0;
    }

    // Allocate memory for the YUV buffer
    unsigned char *yuvBuffer = (unsigned char *)malloc(yuvSize);
    if (yuvBuffer == nullptr) {
        tj3Destroy(handle);
        return 0;
    }

    // Ensure there's enough data for the source image
    int pixelFormat = TJPF_RGB;
    int srcSize = width * height * tjPixelSize[pixelFormat];
    if (size < srcSize + 3) {
        free(yuvBuffer);
        tj3Destroy(handle);
        return 0;
    }

    // Copy the image data into a buffer to ensure it is correctly aligned
    unsigned char *imageBuffer = (unsigned char *)malloc(srcSize);
    if (imageBuffer == nullptr) {
        free(yuvBuffer);
        tj3Destroy(handle);
        return 0;
    }
    memcpy(imageBuffer, data + 3, srcSize);

    // Call the function-under-test
    tj3EncodeYUV8(handle, imageBuffer, width, 0, height, subsamp, yuvBuffer, 0);

    // Clean up
    free(imageBuffer);
    free(yuvBuffer);
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

    LLVMFuzzerTestOneInput_70(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
