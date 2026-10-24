#include <string.h>
#include <sys/stat.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "../src/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_31(const uint8_t *data, size_t size) {
    // Initialize tjhandle
    tjhandle handle = tjInitCompress();
    if (handle == nullptr) {
        return 0;
    }

    // Ensure the input data is large enough for the minimum image size
    if (size < 3) {
        tjDestroy(handle);
        return 0;
    }

    // Dynamically determine image dimensions and pixel format based on input size
    int width = data[0] % 256 + 1;  // Width range: 1 to 256
    int height = data[1] % 256 + 1; // Height range: 1 to 256
    int pixelFormat = data[2] % TJ_NUMPF; // Pixel format based on available formats

    // Calculate required size for the image buffer
    size_t requiredSize = static_cast<size_t>(width * height * tjPixelSize[pixelFormat]);
    if (size < requiredSize) {
        tjDestroy(handle);
        return 0;
    }

    // Define subsampling
    int subsamp = TJSAMP_420; // Example subsampling

    // Allocate memory for YUV planes
    unsigned char *yuvPlanes[3];
    int strides[3];
    strides[0] = tjPlaneWidth(0, width, subsamp);
    strides[1] = tjPlaneWidth(1, width, subsamp);
    strides[2] = tjPlaneWidth(2, width, subsamp);

    yuvPlanes[0] = static_cast<unsigned char *>(malloc(strides[0] * tjPlaneHeight(0, height, subsamp)));
    yuvPlanes[1] = static_cast<unsigned char *>(malloc(strides[1] * tjPlaneHeight(1, height, subsamp)));
    yuvPlanes[2] = static_cast<unsigned char *>(malloc(strides[2] * tjPlaneHeight(2, height, subsamp)));

    if (yuvPlanes[0] == nullptr || yuvPlanes[1] == nullptr || yuvPlanes[2] == nullptr) {
        free(yuvPlanes[0]);
        free(yuvPlanes[1]);
        free(yuvPlanes[2]);
        tjDestroy(handle);
        return 0;
    }

    // Copy the input data to ensure it is not null
    unsigned char *imageBuffer = static_cast<unsigned char *>(malloc(requiredSize));
    if (imageBuffer == nullptr) {
        free(yuvPlanes[0]);
        free(yuvPlanes[1]);
        free(yuvPlanes[2]);
        tjDestroy(handle);
        return 0;
    }
    memcpy(imageBuffer, data, requiredSize);

    // Call the function-under-test
    int result = tjEncodeYUVPlanes(handle, imageBuffer, width, 0, height, pixelFormat, yuvPlanes, strides, subsamp, 0);

    // Clean up
    free(imageBuffer);
    free(yuvPlanes[0]);
    free(yuvPlanes[1]);
    free(yuvPlanes[2]);
    tjDestroy(handle);

    return result;
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

    LLVMFuzzerTestOneInput_31(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
