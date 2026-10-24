#include <stdint.h>
#include <stdlib.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_57(const uint8_t *data, size_t size) {
    // Initialize variables
    tjhandle handle = tjInitCompress();
    if (handle == NULL) {
        return 0; // If initialization fails, exit early
    }

    const unsigned char *yuvPlanes[3];
    int strides[3];
    unsigned char *jpegBuf = NULL;
    unsigned long jpegSize = 0;

    // Ensure the data size is sufficient for YUV planes
    if (size < 3) {
        tjDestroy(handle);
        return 0;
    }

    // Assign data to YUV planes
    yuvPlanes[0] = data;
    yuvPlanes[1] = data + 1;
    yuvPlanes[2] = data + 2;

    // Set strides for each plane
    strides[0] = 1;
    strides[1] = 1;
    strides[2] = 1;

    // Set width, height, and subsampling
    int width = 1;
    int height = 1;
    int subsampling = TJSAMP_444;

    // Set flags
    int flags = 0;

    // Call the function-under-test
    tjCompressFromYUVPlanes(handle, yuvPlanes, width, strides, width, height, &jpegBuf, &jpegSize, subsampling, flags);

    // Clean up
    if (jpegBuf != NULL) {
        tjFree(jpegBuf);
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

    LLVMFuzzerTestOneInput_57(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
