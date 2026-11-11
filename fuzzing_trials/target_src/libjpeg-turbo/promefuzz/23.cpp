// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tj3GetErrorStr at turbojpeg.c:618:17 in turbojpeg.h
// tj3Destroy at turbojpeg.c:580:16 in turbojpeg.h
// tj3Init at turbojpeg.c:538:20 in turbojpeg.h
// tj3GetScalingFactors at turbojpeg.c:1959:28 in turbojpeg.h
// tj3SetScalingFactor at turbojpeg.c:1981:15 in turbojpeg.h
// tjDecompressToYUVPlanes at turbojpeg.c:2291:15 in turbojpeg.h
// tj3Destroy at turbojpeg.c:580:16 in turbojpeg.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <turbojpeg.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>

static void handleError(tjhandle handle) {
    const char *errStr = tj3GetErrorStr(handle);
    if (errStr) {
        fprintf(stderr, "TurboJPEG Error: %s\n", errStr);
    }
    if (handle) {
        tj3Destroy(handle);
    }
}

extern "C" int LLVMFuzzerTestOneInput_23(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize TurboJPEG instance
    int initType = Data[0] % 3; // Randomly choose between 0, 1, 2
    tjhandle handle = tj3Init(initType);
    if (!handle) {
        handleError(handle);
        return 0;
    }

    // Get scaling factors
    int numScalingFactors = 0;
    tjscalingfactor *scalingFactors = tj3GetScalingFactors(&numScalingFactors);
    if (!scalingFactors) {
        handleError(handle);
        return 0;
    }

    // If there are scaling factors, set one
    if (numScalingFactors > 0 && Size > 1) {
        int factorIndex = Data[1] % numScalingFactors;
        if (tj3SetScalingFactor(handle, scalingFactors[factorIndex]) != 0) {
            handleError(handle);
            return 0;
        }
    }

    // Prepare dummy JPEG data
    const unsigned char *jpegBuf = Data;
    unsigned long jpegSize = Size;

    // Decompress to YUV planes if possible
    if (Size > 2) {
        int width = 128; // Example width
        int height = 128; // Example height
        unsigned char *dstPlanes[3] = {nullptr, nullptr, nullptr};
        int strides[3] = {width, width / 2, width / 2};
        for (int i = 0; i < 3; ++i) {
            dstPlanes[i] = (unsigned char *)malloc(width * height);
            if (!dstPlanes[i]) {
                handleError(handle);
                return 0;
            }
        }
        if (tjDecompressToYUVPlanes(handle, jpegBuf, jpegSize, dstPlanes, width, strides, height, 0) != 0) {
            handleError(handle);
            for (int i = 0; i < 3; ++i) {
                free(dstPlanes[i]);
            }
            return 0;
        }
        for (int i = 0; i < 3; ++i) {
            free(dstPlanes[i]);
        }
    }

    // Clean up
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
    