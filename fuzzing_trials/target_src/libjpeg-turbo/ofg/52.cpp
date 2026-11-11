#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_52(const uint8_t *data, size_t size) {
    // Initialize TurboJPEG decompression handle
    tjhandle handle = tjInitDecompress();
    if (handle == nullptr) {
        return 0;
    }

    // Create an array of pointers for YUV planes
    unsigned char *yuvPlanes[3] = { nullptr, nullptr, nullptr };

    // Allocate memory for YUV planes
    int width = 1, height = 1; // Initialize with non-zero values
    int subsamp, colorspace;
    if (tjDecompressHeader3(handle, data, size, &width, &height, &subsamp, &colorspace) == 0) {
        for (int i = 0; i < 3; i++) {
            yuvPlanes[i] = new unsigned char[width * height];
        }
    }

    // Array to hold strides for each plane
    int strides[3] = { width, width / 2, width / 2 };

    // Call the function-under-test
    tj3DecompressToYUVPlanes8(handle, data, size, yuvPlanes, strides);

    // Clean up
    for (int i = 0; i < 3; i++) {
        delete[] yuvPlanes[i];
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

    LLVMFuzzerTestOneInput_52(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
