#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_90(const uint8_t *data, size_t size) {
    tjhandle handle = tjInitDecompress();
    if (handle == nullptr) {
        return 0;
    }

    // Initialize parameters for tjDecompressToYUVPlanes
    unsigned long jpegSize = static_cast<unsigned long>(size);
    int width = 16; // Default width
    int height = 16; // Default height
    int subsamp = TJSAMP_420; // Default subsampling

    // Use the correct function to get the number of planes
    int numPlanes = tjMCUHeight[subsamp] ? 3 : 1;

    unsigned char *yuvPlanes[3];
    int strides[3];

    // Allocate memory for YUV planes
    bool allocationFailed = false;
    for (int i = 0; i < numPlanes; i++) {
        int planeWidth = tjPlaneWidth(i, width, subsamp);
        int planeHeight = tjPlaneHeight(i, height, subsamp);
        yuvPlanes[i] = (unsigned char *)malloc(planeWidth * planeHeight);
        strides[i] = planeWidth;
        if (yuvPlanes[i] == nullptr) {
            allocationFailed = true;
            break;
        }
    }

    // Call the function-under-test if allocation was successful
    if (!allocationFailed) {
        tjDecompressToYUVPlanes(handle, data, jpegSize, yuvPlanes, width, strides, height, subsamp);
    }

    // Free allocated memory
    for (int i = 0; i < numPlanes; i++) {
        if (yuvPlanes[i] != nullptr) {
            free(yuvPlanes[i]);
        }
    }

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

    LLVMFuzzerTestOneInput_90(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
