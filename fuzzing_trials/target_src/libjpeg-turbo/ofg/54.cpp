#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_54(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for the parameters
    if (size < 16) return 0;

    // Initialize tjhandle
    tjhandle handle = tjInitCompress();
    if (!handle) return 0;

    // Extract parameters from data
    const unsigned char *srcBuf = data;
    int width = (int)data[0] + 1;  // Avoid zero width
    int height = (int)data[1] + 1; // Avoid zero height
    int pitch = width * 3; // Assuming 3 bytes per pixel (RGB)
    int subsamp = TJSAMP_444; // Use a valid subsampling option

    // Allocate YUV planes
    unsigned char *yuvPlanes[3];
    int yuvStrides[3];
    int planeSize = tjBufSizeYUV2(width, 1, height, subsamp);
    for (int i = 0; i < 3; i++) {
        yuvPlanes[i] = (unsigned char *)malloc(planeSize);
        if (!yuvPlanes[i]) {
            for (int j = 0; j < i; j++) {
                free(yuvPlanes[j]);
            }
            tjDestroy(handle);
            return 0;
        }
        yuvStrides[i] = width;
        memset(yuvPlanes[i], 0, planeSize); // Initialize allocated memory
    }

    // Call the function-under-test
    tj3EncodeYUVPlanes8(handle, srcBuf, width, pitch, height, subsamp, yuvPlanes, yuvStrides);

    // Clean up
    for (int i = 0; i < 3; i++) {
        free(yuvPlanes[i]);
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

    LLVMFuzzerTestOneInput_54(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
