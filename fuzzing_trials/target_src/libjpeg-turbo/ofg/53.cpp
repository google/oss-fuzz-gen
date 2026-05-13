#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_53(const uint8_t *data, size_t size) {
    tjhandle handle = tj3Init(TJINIT_DECOMPRESS);
    if (!handle) {
        return 0;
    }

    // Allocate memory for YUV planes
    unsigned char *yuvPlanes[3];
    int yuvSizes[3];
    for (int i = 0; i < 3; ++i) {
        yuvSizes[i] = (size / 3) + 1; // Ensure non-zero size
        yuvPlanes[i] = static_cast<unsigned char *>(malloc(yuvSizes[i]));
        if (!yuvPlanes[i]) {
            for (int j = 0; j < i; ++j) {
                free(yuvPlanes[j]);
            }
            tj3Destroy(handle);
            return 0;
        }
        memset(yuvPlanes[i], 0, yuvSizes[i]);
    }

    // Call the function-under-test
    tj3DecompressToYUVPlanes8(handle, data, size, yuvPlanes, yuvSizes);

    // Free allocated memory
    for (int i = 0; i < 3; ++i) {
        free(yuvPlanes[i]);
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

    LLVMFuzzerTestOneInput_53(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
