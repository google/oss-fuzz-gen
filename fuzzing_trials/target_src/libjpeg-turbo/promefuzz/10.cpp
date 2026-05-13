// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// TJBUFSIZEYUV at turbojpeg.c:1013:25 in turbojpeg.h
// tjBufSizeYUV at turbojpeg.c:1007:25 in turbojpeg.h
// tj3YUVPlaneSize at turbojpeg.c:1020:18 in turbojpeg.h
// tjPlaneSizeYUV at turbojpeg.c:1048:25 in turbojpeg.h
// tjBufSize at turbojpeg.c:933:25 in turbojpeg.h
// tjBufSizeYUV2 at turbojpeg.c:999:25 in turbojpeg.h
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
#include <iostream>
#include <fstream>

extern "C" int LLVMFuzzerTestOneInput_10(const uint8_t *Data, size_t Size) {
    if (Size < 24) return 0; // Ensure enough data for all parameters

    int width = static_cast<int>(Data[0] + (Data[1] << 8));
    int height = static_cast<int>(Data[2] + (Data[3] << 8));
    int subsamp = Data[4] % 6; // Valid subsampling values are 0 to 5
    int componentID = Data[5] % 3; // Valid component IDs are 0, 1, 2
    int stride = static_cast<int>(Data[6] + (Data[7] << 8));
    int align = Data[8] % 16; // Alignment values typically small
    int jpegSubsamp = Data[9] % 6; // Valid subsampling values are 0 to 5

    // Fuzz tjBufSizeYUV
    try {
        unsigned long bufSizeYUV = tjBufSizeYUV(width, height, subsamp);
        (void)bufSizeYUV;
    } catch (...) {
        // Handle exceptions if any
    }

    // Fuzz tjPlaneSizeYUV
    try {
        unsigned long planeSizeYUV = tjPlaneSizeYUV(componentID, width, stride, height, subsamp);
        (void)planeSizeYUV;
    } catch (...) {
        // Handle exceptions if any
    }

    // Fuzz tjBufSize
    try {
        unsigned long bufSize = tjBufSize(width, height, jpegSubsamp);
        (void)bufSize;
    } catch (...) {
        // Handle exceptions if any
    }

    // Fuzz tj3YUVPlaneSize
    try {
        size_t yuvPlaneSize = tj3YUVPlaneSize(componentID, width, stride, height, subsamp);
        (void)yuvPlaneSize;
    } catch (...) {
        // Handle exceptions if any
    }

    // Fuzz tjBufSizeYUV2
    try {
        unsigned long bufSizeYUV2 = tjBufSizeYUV2(width, align, height, subsamp);
        (void)bufSizeYUV2;
    } catch (...) {
        // Handle exceptions if any
    }

    // Fuzz TJBUFSIZEYUV
    try {
        unsigned long bufSizeYUV3 = TJBUFSIZEYUV(width, height, jpegSubsamp);
        (void)bufSizeYUV3;
    } catch (...) {
        // Handle exceptions if any
    }

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

        LLVMFuzzerTestOneInput_10(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    