#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_91(const uint8_t *data, size_t size) {
    tjhandle handle = nullptr;
    unsigned char *yuvPlanes[3] = {nullptr, nullptr, nullptr};
    int strides[3] = {0, 0, 0};
    int width = 0;
    int height = 0;
    int subsamp = TJSAMP_444; // Default subsampling
    int flags = 0; // Default flags

    // Initialize TurboJPEG decompressor
    handle = tjInitDecompress();
    if (handle == nullptr) {
        return 0;
    }

    // Retrieve the width, height, and subsampling from the JPEG header
    if (tjDecompressHeader2(handle, const_cast<unsigned char*>(data), size, &width, &height, &subsamp) != 0) {
        tjDestroy(handle);
        return 0;
    }

    // Allocate memory for YUV planes
    for (int i = 0; i < 3; i++) {
        yuvPlanes[i] = (unsigned char *)malloc(tjPlaneSizeYUV(i, width, strides[i], height, subsamp));
        if (yuvPlanes[i] == nullptr) {
            for (int j = 0; j < i; j++) {
                free(yuvPlanes[j]);
            }
            tjDestroy(handle);
            return 0;
        }
    }

    // Set strides for YUV planes
    strides[0] = TJPAD(width);
    strides[1] = strides[2] = TJPAD(width / 2);

    // Call the function-under-test
    tjDecompressToYUVPlanes(handle, const_cast<unsigned char*>(data), size, yuvPlanes, width, strides, height, flags);

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

    LLVMFuzzerTestOneInput_91(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
